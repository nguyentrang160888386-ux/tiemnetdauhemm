import {
  assertFails,
  assertSucceeds,
  initializeTestEnvironment,
  RulesTestEnvironment,
} from '@firebase/rules-unit-testing';
import fs from 'fs';

describe('Net Co Dau Hem Firestore Security Rules - Dirty Dozen Tests', () => {
  let testEnv: RulesTestEnvironment;

  beforeAll(async () => {
    testEnv = await initializeTestEnvironment({
      projectId: 'tiemnetdauhem-test',
      firestore: {
        rules: fs.readFileSync('firestore.rules', 'utf8'),
      },
    });
  });

  afterAll(async () => {
    if (testEnv) {
      await testEnv.cleanup();
    }
  });

  test('1. Cross-User Save Read is denied', async () => {
    const alice = testEnv.authenticatedContext('user_A', { email_verified: true });
    const bob = testEnv.authenticatedContext('user_B', { email_verified: true });
    await testEnv.withSecurityRulesDisabled(async (ctx) => {
      await ctx.firestore().doc('saves/user_A').set({
        blob: '{"S":{"day":1}}',
        day: 1,
        cash: 500,
        device: 'Mozilla/5.0',
        updated_at: '2026-10-30T00:00:00.000Z',
        ts: new Date(),
      });
    });
    await assertFails(bob.firestore().doc('saves/user_A').get());
    await assertSucceeds(alice.firestore().doc('saves/user_A').get());
  });

  test('2. Unverified Email Save Write is denied', async () => {
    const unverified = testEnv.authenticatedContext('user_A', { email_verified: false });
    await assertFails(
      unverified.firestore().doc('saves/user_A').set({
        blob: '{"S":{"day":1}}',
        day: 1,
        cash: 500,
        device: 'Mozilla/5.0',
        updated_at: '2026-10-30T00:00:00.000Z',
        ts: new Date(),
      })
    );
  });

  test('3. Shadow Field Injection on Save is denied', async () => {
    const alice = testEnv.authenticatedContext('user_A', { email_verified: true });
    await assertFails(
      alice.firestore().doc('saves/user_A').set({
        blob: '{"S":{"day":1}}',
        day: 1,
        cash: 500,
        device: 'Mozilla/5.0',
        updated_at: '2026-10-30T00:00:00.000Z',
        ts: new Date(),
        isAdmin: true,
      })
    );
  });

  test('4. Oversized Blob on Save is denied', async () => {
    const alice = testEnv.authenticatedContext('user_A', { email_verified: true });
    await assertFails(
      alice.firestore().doc('saves/user_A').set({
        blob: 'x'.repeat(900005),
        day: 1,
        cash: 500,
        device: 'Mozilla/5.0',
        updated_at: '2026-10-30T00:00:00.000Z',
        ts: new Date(),
      })
    );
  });

  test('5. Forged Client Timestamp on Save is denied', async () => {
    const alice = testEnv.authenticatedContext('user_A', { email_verified: true });
    await assertFails(
      alice.firestore().doc('saves/user_A').set({
        blob: '{"S":{"day":1}}',
        day: 1,
        cash: 500,
        device: 'Mozilla/5.0',
        updated_at: '2026-10-30T00:00:00.000Z',
        ts: new Date(Date.now() - 86400000),
      })
    );
  });

  test('6. Cross-User Leaderboard Spoofing is denied', async () => {
    const bob = testEnv.authenticatedContext('user_B', { email_verified: true });
    await assertFails(
      bob.firestore().doc('players/user_A').set({
        nick: 'Hacker',
        shop: 'Net Hack',
        day: 99,
        lvl: 10,
        branch: 1,
        cash: 999999,
        rating: 5,
        hot: 100,
        served: 1000,
        pcs: 20,
        staff: 4,
        slogan: 'Hi',
        fish: 0,
        ts: new Date(),
        expireAt: new Date(Date.now() + 1000000),
      })
    );
  });

  test('7. Value Poisoning on Leaderboard Update is denied', async () => {
    const alice = testEnv.authenticatedContext('user_A', { email_verified: true });
    await assertFails(
      alice.firestore().doc('players/user_A').set({
        nick: 'A'.repeat(100),
        shop: 'Net Co',
        day: 1,
        lvl: 1,
        branch: 0,
        cash: 'invalid_number',
        rating: 4,
        hot: 10,
        served: 5,
        pcs: 4,
        staff: 0,
        slogan: '',
        fish: 0,
        ts: new Date(),
        expireAt: new Date(Date.now() + 1000000),
      })
    );
  });

  test('8. Nickname Hijacking is denied', async () => {
    const bob = testEnv.authenticatedContext('user_B', { email_verified: true });
    await testEnv.withSecurityRulesDisabled(async (ctx) => {
      await ctx.firestore().doc('nicks/pro_gamer').set({
        uid: 'user_A',
        nick: 'Pro Gamer',
      });
    });
    await assertFails(
      bob.firestore().doc('nicks/pro_gamer').set({
        uid: 'user_B',
        nick: 'Pro Gamer',
      })
    );
  });

  test('9. Nickname Spoofed UID Creation is denied', async () => {
    const alice = testEnv.authenticatedContext('user_A', { email_verified: true });
    await assertFails(
      alice.firestore().doc('nicks/new_nick').set({
        uid: 'user_B',
        nick: 'New Nick',
      })
    );
  });

  test('10. Foreign Nickname Deletion is denied', async () => {
    const bob = testEnv.authenticatedContext('user_B', { email_verified: true });
    await assertFails(bob.firestore().doc('nicks/pro_gamer').delete());
  });

  test('11. Orphaned Telemetry Event Write is denied', async () => {
    const anon = testEnv.authenticatedContext('anon_1', {});
    await assertFails(
      anon.firestore().doc('telemetry/anon_1/events/ev_1').set({
        ev: 'app_open',
        p: {},
        ts: new Date(),
        expireAt: new Date(Date.now() + 1000000),
      })
    );
  });

  test('12. Path ID Poisoning is denied', async () => {
    const alice = testEnv.authenticatedContext('user_A', { email_verified: true });
    await assertFails(
      alice.firestore().doc('nicks/bad id with spaces!').set({
        uid: 'user_A',
        nick: 'Bad ID',
      })
    );
  });
});
