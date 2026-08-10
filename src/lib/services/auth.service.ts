import { authDb } from '../database/auth.db';
import { systemDb } from '../database/system.db';
import { User, UserRole, Invite } from '../types';
import { UserDomain } from '../domain/user.domain';
import { validatePassword, validateEmail, normalizeEmail } from '../validation';
import { serverSessionCache } from '../auth/server-session';
import { UserMapper } from '../mappers';
import { rbac } from '../auth/rbac';
import { comparePassword, hashPassword, generateToken, hashToken } from '../crypto';
import { USER_ROLES, SIGNUP_LIMITS } from '../constants';
import { BadRequestError, UnauthorizedError, ForbiddenError, NotFoundError, ConflictError } from '../api-error';

export class AuthService {
  async validateSession(token: string): Promise<User | null> {
    const tokenHash = await hashToken(token);

    const cachedUser = serverSessionCache.get(tokenHash);
    if (cachedUser) {
        return { ...cachedUser, sessionId: tokenHash } as User;
    }

    const session = await authDb.findSessionByHash(tokenHash);
    if (!session || new Date(session.expires_at) < new Date()) {
      return null;
    }
    const user = await systemDb.findUserById(session.user_id);
    if (!user) return null;

    // Safety check: sessions are invalid for deactivated or locked users
    if (user.active === false || (user.locked_until && new Date(user.locked_until) > new Date())) {
        await authDb.deleteSessionByHash(tokenHash);
        serverSessionCache.invalidate(tokenHash);
        return null;
    }

    // Version-based cache invalidation
    if (cachedUser && (cachedUser as User).version !== user.version) {
        serverSessionCache.invalidate(tokenHash);
    }

    const userDTO = UserMapper.toDTO(user);
    if (!userDTO) return null;

    userDTO.password_change_required = user.reset_request?.status === 'approved_used';

    serverSessionCache.set(tokenHash, userDTO);

    return { ...user, sessionId: tokenHash, password_change_required: userDTO.password_change_required } as User;
  }

  async createSession(userId: string): Promise<string> {
    await authDb.deleteUserSessions(userId);
    serverSessionCache.invalidateAllForUser(userId);

    const token = generateToken();
    const tokenHash = await hashToken(token);

    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    await authDb.createSession(userId, expiresAt, tokenHash);
    return token;
  }

  async logout(token: string): Promise<void> {
    const tokenHash = await hashToken(token);
    await authDb.deleteSessionByHash(tokenHash);
    serverSessionCache.invalidate(tokenHash);
  }

  async authenticate(email: string, password?: string): Promise<{ success: boolean; user: User; session_id: string }> {
    const user = await systemDb.findUserByEmail(email);
    if (!user) {
      throw new NotFoundError('Email not found');
    }

    if (!user.active) {
      throw new BadRequestError('Account is deactivated');
    }

    if (user.flagged) {
      throw new BadRequestError('Account is flagged. Please contact support.');
    }

    const now = new Date();
    if (user.locked_until && new Date(user.locked_until) > now) {
      throw new BadRequestError(`LOCKOUT:${new Date(user.locked_until).getTime()}`);
    }

    if (user.reset_request && user.reset_request.status === 'approved_used') {
       throw new BadRequestError('Your session has expired. You must change your password using the secure prompt provided during your first login.');
    }

    const isPasswordValid = password && user.password && await comparePassword(password, user.password);
    if (!isPasswordValid) {
      if (user.reset_request) {
        const reset = user.reset_request;
        if (reset.status === 'pending') {
          throw new BadRequestError('Your password reset request is under review.');
        } else if (reset.status === 'approved' && reset.expires_at) {
          if (new Date(reset.expires_at) > now) {
            throw new BadRequestError(`Reset approved. Your temp password is: ${reset.temp_password}`);
          }
        } else if (reset.status === 'denied') {
          throw new BadRequestError(`Reset denied: ${reset.denial_reason}`);
        }
      }

      const failedAttempts = (user.failed_attempts || 0) + 1;
      const newLockouts = failedAttempts >= 5 ? (user.lockouts || 0) + 1 : user.lockouts;
      const lockedUntil = failedAttempts >= 5 ? new Date(Date.now() + 30 * 60 * 1000).toISOString() : user.locked_until;

      const updates: Record<string, unknown> = {
        failed_attempts: failedAttempts,
        locked_until: lockedUntil,
        lockouts: newLockouts,
        flagged: (newLockouts || 0) >= 3 ? true : user.flagged
      };
      await authDb.updateUserRaw(user.id, updates);

      if (failedAttempts >= 5) {
          throw new BadRequestError(`LOCKOUT:${new Date(lockedUntil as string).getTime()}`);
      }

      throw new BadRequestError(`Incorrect password. ${5 - failedAttempts} attempts remaining.`);
    }

    if (user.reset_request && user.reset_request.status === 'approved') {
       const reset = user.reset_request;
       if (reset.expires_at && new Date(reset.expires_at) < now) {
          throw new BadRequestError('Temporary password has expired. Please request a new one.');
       }
       const newResetRequest: NonNullable<User['reset_request']> = { ...reset, status: 'approved_used' };
       delete newResetRequest.temp_password;

       // Use atomic consumption to prevent race conditions
       const consumed = await authDb.consumeTempPassword(user.id, newResetRequest);
       if (!consumed) {
          throw new BadRequestError('Temporary password has already been used or is no longer valid.');
       }
    }

    await authDb.updateUserRaw(user.id, { last_login: now.toISOString(), failed_attempts: 0, locked_until: null });

    // Explicitly create session and get token
    const token = await this.createSession(user.id);

    const { serviceRegistry } = await import('./service-registry');
    serviceRegistry.systemService.performSystemCleanup(await hashToken(token)).catch(console.error);

    return {
        success: true,
        user: { ...user, password_change_required: user.reset_request?.status === 'approved_used' },
        session_id: token
    };
  }

  async signup(data: { full_name: string; email: string; password?: string; phone?: string; role: UserRole }, inviteId?: string): Promise<{ success: boolean; user: User; session_id: string }> {
    if (!data.password || data.password.trim() === '') {
      throw new BadRequestError('Password is required');
    }

    const existingUser = await systemDb.findUserByEmail(data.email);
    if (existingUser) {
      throw new ConflictError('An account with this email already exists.');
    }

    const passwordValidation = validatePassword(data.password);
    if (!passwordValidation.isValid) {
      throw new BadRequestError(passwordValidation.errors[0].message);
    }

    // Server-side role validation and limit enforcement
    const allowedRoles: UserRole[] = [USER_ROLES.STUDENT, USER_ROLES.TEACHER, USER_ROLES.ADMIN];
    if (!allowedRoles.includes(data.role)) {
      throw new BadRequestError('Invalid role specified');
    }

    // Public signup limits do NOT apply to invites
    if (!inviteId && (data.role === USER_ROLES.TEACHER || data.role === USER_ROLES.ADMIN)) {
      const count = await this.getRoleUserCount(data.role);
      const limit = data.role === USER_ROLES.TEACHER ? SIGNUP_LIMITS.TEACHER : SIGNUP_LIMITS.ADMIN;
      if (count >= limit) {
        throw new BadRequestError(`Public creation limit reached for ${data.role}s. Please contact support.`);
      }
    }

    // Authoritative DB validation of invitation state if inviteId is supplied
    let inviteToUse: Invite | null = null;
    if (inviteId) {
      inviteToUse = await authDb.findInviteById(inviteId);
      if (!inviteToUse) {
        throw new BadRequestError('Invalid invite token');
      }

      if (inviteToUse.used_at) {
        throw new BadRequestError('Invite has already been used');
      }

      if (new Date(inviteToUse.expires_at) < new Date()) {
        throw new BadRequestError('Invite has expired');
      }

      if (inviteToUse.role !== data.role) {
        throw new BadRequestError(`This invite is only valid for the role: ${inviteToUse.role}`);
      }

      if (inviteToUse.type === 'email_bound') {
        if (!inviteToUse.email) {
          throw new BadRequestError('Invalid email-bound invite state');
        }
        if (normalizeEmail(inviteToUse.email) !== normalizeEmail(data.email)) {
          throw new BadRequestError(`This invite is bound to the email address: ${inviteToUse.email}`);
        }
      }

      // Atomic consumption of invite *before* registration
      const consumed = await authDb.consumeInvite(inviteId);
      if (!consumed) {
        throw new BadRequestError('Invite has already been used or is invalid');
      }
    }

    try {
      const hashedPassword = await hashPassword(data.password);
      const { data: userData, error } = await authDb.register({
        full_name: data.full_name,
        email: data.email,
        password: hashedPassword,
        phone: data.phone,
        role: data.role,
        active: true
      });

      if (error) throw new BadRequestError(`Signup failed in database: ${error.message || 'Unknown error'}`);

      const newUser = userData as User;

      // Explicitly create session and get token
      const token = await this.createSession(newUser.id);

      return {
          success: true,
          user: newUser,
          session_id: token
      };
    } catch (err) {
      // Revert/rollback invite consumption if registration failed
      if (inviteId) {
        await authDb.unconsumeInvite(inviteId);
      }
      throw err;
    }
  }

  async generateInvite(currentUser: User, role: UserRole, email?: string): Promise<{ token: string; link: string }> {
    if (!rbac.can(currentUser, 'user:manage')) {
        throw new ForbiddenError('Only admins can generate invites');
    }

    if ((role === 'admin' || role === 'teacher') && !email) {
        throw new BadRequestError('Email is required for admin and teacher invites');
    }

    let normalizedEmail: string | undefined;
    if (email) {
        const emailValidation = validateEmail(email);
        if (!emailValidation.isValid) {
            throw new BadRequestError(emailValidation.errors[0].message);
        }
        normalizedEmail = normalizeEmail(email);
    }

    const rawToken = generateToken();
    const tokenHash = await hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    await authDb.createInvite({
        token_hash: tokenHash,
        email: normalizedEmail,
        role,
        type: (role === 'admin' || role === 'teacher') ? 'email_bound' : 'role_only',
        created_by: currentUser.id,
        expires_at: expiresAt
    });

    const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://kajas.vercel.app';
    const link = `${baseUrl}/api/v1/auth/invite/accept?token=${rawToken}`;

    return { token: rawToken, link };
  }

  async validateInvite(token: string): Promise<Invite> {
    const tokenHash = await hashToken(token);
    const invite = await authDb.findInviteByHash(tokenHash);

    if (!invite) {
        throw new BadRequestError('Invalid invite token');
    }

    if (invite.used_at) {
        throw new BadRequestError('Invite has already been used');
    }

    if (new Date(invite.expires_at) < new Date()) {
        throw new BadRequestError('Invite has expired');
    }

    return invite;
  }

  async createUser(currentUser: User, data: { full_name: string; email: string; password?: string; phone?: string; role: UserRole }): Promise<User> {
    if (!rbac.can(currentUser, 'user:manage')) {
        throw new ForbiddenError('Only admins can create users directly');
    }

    if (!data.password || data.password.trim() === '') {
      throw new BadRequestError('Password is required');
    }

    const passwordValidation = validatePassword(data.password);
    if (!passwordValidation.isValid) {
      throw new BadRequestError(passwordValidation.errors[0].message);
    }

    const hashedPassword = await hashPassword(data.password);
    const { data: userData, error } = await authDb.register({
      full_name: data.full_name,
      email: data.email,
      password: hashedPassword,
      phone: data.phone,
      role: data.role,
      active: true
    });

    if (error) throw new Error('Failed to create user in database');
    return userData as User;
  }

  async updatePassword(currentPass: string, newPass: string, token: string) {
    const sessionUser = await this.validateSession(token);
    if (!sessionUser) throw new UnauthorizedError();

    const user = await systemDb.findUserById(sessionUser.id as string, sessionUser.sessionId);
    if (!user) throw new BadRequestError('User not found');

    const isPasswordValid = user.password && await comparePassword(currentPass, user.password);
    if (!isPasswordValid) throw new BadRequestError('Incorrect current password');

    const hashedPassword = await hashPassword(newPass);
    await authDb.updateUserRaw(user.id, { password: hashedPassword, reset_request: null }, sessionUser.sessionId);

    await authDb.deleteUserSessions(user.id);
    serverSessionCache.invalidateAllForUser(user.id);

    return { success: true };
  }

  async requestPasswordReset(email: string, reason: string, riskLevel: string) {
    const user = await systemDb.findUserByEmail(email);
    if (!user) throw new BadRequestError('No account found with this email.');

    if (user.reset_request) {
      const reset = user.reset_request;
      if (reset.status === 'pending') {
        throw new BadRequestError('A request is already under review for this account.');
      } else if (reset.status === 'approved' && reset.expires_at && new Date(reset.expires_at) > new Date()) {
        throw new BadRequestError(`Reset approved. Temp Password: ${reset.temp_password}`);
      }
    }

    const resetRequest: NonNullable<User['reset_request']> = {
      requested_at: new Date().toISOString(),
      status: 'pending',
      reason,
      risk_level: riskLevel
    };

    await authDb.updateUserRaw(user.id, {
      reset_request: resetRequest,
      flagged: riskLevel === 'high' ? true : user.flagged
    });

    return { success: true };
  }

  async approvePasswordReset(userId: string, tempPassword: string, currentUser: User) {
    const hashedPassword = await hashPassword(tempPassword);

    const user = await systemDb.findUserById(userId, currentUser.sessionId);
    if (!user) throw new BadRequestError('User not found');

    const resetRequest: NonNullable<User['reset_request']> = {
      ...(user.reset_request || { status: 'pending', requested_at: new Date().toISOString() }),
      status: 'approved',
      temp_password: tempPassword,
      approved_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    };

    await authDb.updateUserRaw(userId, {
      password: hashedPassword,
      reset_request: resetRequest,
      failed_attempts: 0,
      locked_until: null
    }, currentUser.sessionId);

    return { success: true };
  }

  async denyPasswordReset(userId: string, reason: string, currentUser: User) {
    const user = await systemDb.findUserById(userId, currentUser.sessionId);
    if (!user) throw new BadRequestError('User not found');

    const resetRequest: NonNullable<User['reset_request']> = {
      ...(user.reset_request || { status: 'pending', requested_at: new Date().toISOString() }),
      status: 'denied',
      denial_reason: reason
    };

    await authDb.updateUserRaw(userId, { reset_request: resetRequest }, currentUser.sessionId);

    return { success: true };
  }

  async updatePreferences(preferences: Record<string, boolean>, currentUser: User) {
    await authDb.updateUserRaw(currentUser.id, { notification_preferences: preferences }, currentUser.sessionId);
    return { success: true };
  }

  async getSessions(currentUser: User) {
    const userId = currentUser.role === 'admin' ? undefined : currentUser.id;
    return authDb.findAllSessions(currentUser.sessionId!, userId);
  }

  async getRoleCount() {
    const [teachers, admins, total] = await Promise.all([
        systemDb.countUsersByRole(USER_ROLES.TEACHER),
        systemDb.countUsersByRole(USER_ROLES.ADMIN),
        systemDb.countUsersByRole()
    ]);
    return { teachers, admins, total };
  }

  async getRoleUserCount(role: string): Promise<number> {
    return systemDb.countUsersByRole(role);
  }

  async getCurrentUser(id: string, sessionId: string): Promise<User> {
    const user = await systemDb.findUserById(id, sessionId);
    if (!user) throw new BadRequestError('User not found');
    return { ...user, sessionId };
  }

  async getAllUsers(currentUser: User, limit?: number, offset?: number): Promise<User[]> {
    if (!rbac.can(currentUser, 'user:manage')) throw new ForbiddenError('Forbidden');
    return systemDb.findAllUsers(currentUser.sessionId!, { limit, offset });
  }

  async updateUserProfile(currentUser: User, userId: string, updates: Partial<User>, sessionId: string): Promise<User> {
    const targetUser = await systemDb.findUserById(userId, sessionId);
    if (!targetUser) throw new BadRequestError('User not found');

    UserDomain.validateUpdate(currentUser, userId);

    if (rbac.can(currentUser, 'user:manage')) {
        await systemDb.adminUpdateUser(userId, updates, sessionId);
        return (await systemDb.findUserById(userId, sessionId))!;
    }

    const filteredUpdates = UserDomain.filterUpdateFields(currentUser, updates);
    return systemDb.updateUser(userId, { ...filteredUpdates, version: targetUser.version }, sessionId);
  }

  async toggleUserStatus(currentUser: User, userId: string, active: boolean): Promise<void> {
    if (!rbac.can(currentUser, 'user:manage')) throw new ForbiddenError('Forbidden');
    const targetUser = await systemDb.findUserById(userId, currentUser.sessionId);
    if (!targetUser) throw new BadRequestError('User not found');
    await systemDb.updateUser(userId, { active, version: targetUser.version }, currentUser.sessionId!);
  }

  async deleteUser(currentUser: User, userId: string): Promise<void> {
    if (!rbac.can(currentUser, 'user:manage')) throw new ForbiddenError('Forbidden');
    await systemDb.deleteUser(userId, currentUser.sessionId!);
  }
}

export const authService = new AuthService();
