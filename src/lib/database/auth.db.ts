import { withSession, supabase } from '../supabase';
import { adminClient } from '../supabase-admin';
import { Session, User, DatabaseResponse, DatabaseError, Invite } from '../types';
import { dbUtils } from './db-utils';

export const authDb = {
  async register(data: { full_name: string; email: string; password?: string; phone?: string; role: string; active?: boolean }): Promise<DatabaseResponse<User>> {
    // Registration often happens without an active session (public signup)
    const client = adminClient || supabase;
    const { data: userData, error } = await client.from('users').insert(data).select().single();
    return { data: userData as User, error: error as DatabaseError | null };
  },

  async updateUserRaw(id: string, updates: Partial<User>, sessionId?: string): Promise<DatabaseResponse<User>> {
    // Prefer RLS-enforced client when sessionId is available
    const client = (sessionId && adminClient) ? supabase : (adminClient || supabase);
    let query = client.from('users').update(updates).eq('id', id);
    if (sessionId) query = withSession(query, sessionId);
    const { data, error } = await query.select().single();
    return { data: data as User, error };
  },

  // Session Table Operations (Original SessionRepository)
  async findSessionByHash(tokenHash: string): Promise<Session | null> {
    // Used for session validation, usually requires admin bypass or specific header
    const client = adminClient || supabase;
    const { data, error } = await client
      .from('sessions')
      .select('*')
      .eq('token_hash', tokenHash)
      .single();

    if (error) {
      if (error.code === 'PGRST116') return null;
      dbUtils.handleError(error);
    }
    return data as Session;
  },

  async createSession(userId: string, expiresAt: string, tokenHash: string): Promise<Session> {
    const client = adminClient || supabase;
    const { data, error } = await client
      .from('sessions')
      .insert({
        user_id: userId,
        expires_at: expiresAt,
        token_hash: tokenHash
      })
      .select()
      .single();

    if (error) dbUtils.handleError(error);
    return data as Session;
  },

  async deleteSessionByHash(tokenHash: string): Promise<void> {
    const client = adminClient || supabase;
    const { error } = await client
      .from('sessions')
      .delete()
      .eq('token_hash', tokenHash);

    if (error) dbUtils.handleError(error);
  },

  async deleteUserSessions(userId: string, exceptHash?: string): Promise<void> {
    const client = adminClient || supabase;
    let query = client.from('sessions').delete().eq('user_id', userId);
    if (exceptHash) {
      query = query.neq('token_hash', exceptHash);
    }
    const { error } = await query;
    if (error) dbUtils.handleError(error);
  },

  async findAllSessions(sessionId: string, userId?: string): Promise<Session[]> {
    // Prefer RLS-enforced client
    const client = (sessionId && adminClient) ? supabase : (adminClient || supabase);
    let query = client.from('sessions').select('*');
    if (sessionId) query = withSession(query, sessionId);
    if (userId) query = query.eq('user_id', userId);
    const { data, error } = await query;
    if (error) dbUtils.handleError(error);
    return data as Session[];
  },

  async consumeTempPassword(userId: string, newResetRequest: NonNullable<User['reset_request']>, sessionId?: string): Promise<boolean> {
    const client = (sessionId && adminClient) ? supabase : (adminClient || supabase);
    let query = client
      .from('users')
      .update({ reset_request: newResetRequest })
      .eq('id', userId)
      .filter('reset_request->>status', 'eq', 'approved');

    if (sessionId) query = withSession(query, sessionId);
    const { data, error } = await query.select('id');

    if (error) dbUtils.handleError(error);
    return !!data && data.length > 0;
  },

  // Invite Operations
  async createInvite(data: Omit<Invite, 'id' | 'created_at'>): Promise<Invite> {
    const client = adminClient || supabase;
    const { data: invite, error } = await client
      .from('invites')
      .insert(data)
      .select()
      .single();

    if (error) dbUtils.handleError(error);
    return invite as Invite;
  },

  async findInviteByHash(tokenHash: string): Promise<Invite | null> {
    const client = adminClient || supabase;
    const { data, error } = await client
      .from('invites')
      .select('*')
      .eq('token_hash', tokenHash)
      .single();

    if (error) {
      if (error.code === 'PGRST116') return null;
      dbUtils.handleError(error);
    }
    return data as Invite;
  },

  async findInviteById(id: string): Promise<Invite | null> {
    const client = adminClient || supabase;
    const { data, error } = await client
      .from('invites')
      .select('*')
      .eq('id', id)
      .single();

    if (error) {
      if (error.code === 'PGRST116') return null;
      dbUtils.handleError(error);
    }
    return data as Invite;
  },

  async consumeInvite(id: string): Promise<boolean> {
    const client = adminClient || supabase;
    const { data, error } = await client
      .from('invites')
      .update({ used_at: new Date().toISOString() })
      .eq('id', id)
      .is('used_at', null)
      .select('id');

    if (error) dbUtils.handleError(error);
    return !!data && data.length > 0;
  },

  async unconsumeInvite(id: string): Promise<void> {
    const client = adminClient || supabase;
    const { error } = await client
      .from('invites')
      .update({ used_at: null })
      .eq('id', id);

    if (error) dbUtils.handleError(error);
  },

  async markInviteAsUsed(id: string): Promise<void> {
    const client = adminClient || supabase;
    const { error } = await client
      .from('invites')
      .update({ used_at: new Date().toISOString() })
      .eq('id', id);

    if (error) dbUtils.handleError(error);
  }
};
