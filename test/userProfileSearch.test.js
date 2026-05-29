const test = require('node:test');
const assert = require('node:assert/strict');

const {
  usernameSearchFilters,
  queryUsersByUsername,
} = require('../src/modules/users/application/userProfileService');

function makeUserModel(seed) {
  return {
    find(filter) {
      const matches = seed.filter((user) => {
        if (filter.id?.$ne && user.id === filter.id.$ne) return false
        const regex = filter.username?.$regex
        const options = filter.username?.$options || ''
        if (!regex) return false
        const re = new RegExp(regex, options.includes('i') ? 'i' : '')
        return re.test(user.username)
      })
      return {
        limit(n) {
          return {
            lean: async () => matches.slice(0, n),
          }
        },
      }
    },
  }
}

test('usernameSearchFilters prefers exact, then prefix, then contains', () => {
  const filters = usernameSearchFilters('alice');
  assert.equal(filters.length, 3);
  assert.match(String(filters[0].username.$regex), /\$$/);
  assert.match(String(filters[1].username.$regex), /^\^/);
});

test('queryUsersByUsername finds case-insensitive exact matches', async () => {
  const User = makeUserModel([{ id: 'U1', username: 'Alice', aboutme: '', profilePicture: '', banner: '' }]);
  const docs = await queryUsersByUsername(User, { searchTerm: 'alice' });
  assert.equal(docs.length, 1);
  assert.equal(docs[0].username, 'Alice');
});

test('queryUsersByUsername finds substring matches when prefix fails', async () => {
  const User = makeUserModel([{ id: 'U2', username: 'JohnDoe', aboutme: '', profilePicture: '', banner: '' }]);
  const docs = await queryUsersByUsername(User, { searchTerm: 'doe' });
  assert.equal(docs.length, 1);
  assert.equal(docs[0].id, 'U2');
});
