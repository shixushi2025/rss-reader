const els = {
  feedList: document.getElementById('feed-list'),
  itemList: document.getElementById('item-list'),
  itemsTitle: document.getElementById('items-title'),
  status: document.getElementById('status'),
  addFeedForm: document.getElementById('add-feed-form'),
  feedUrl: document.getElementById('feed-url'),
  btnRefresh: document.getElementById('btn-refresh'),
  btnToggleFeeds: document.getElementById('btn-toggle-feeds'),
  btnCloseFeeds: document.getElementById('btn-close-feeds'),
  feedsBackdrop: document.getElementById('feeds-backdrop'),
  unreadOnly: document.getElementById('unread-only'),
  btnMore: document.getElementById('btn-more'),
  btnMarkAllRead: document.getElementById('btn-mark-all-read'),
};

let state = {
  feeds: [],
  selectedFeedId: null, // null means "All"
  unreadOnly: false,
  cursor: null, // for pagination
  loading: false,
};

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toLocaleString();
}

function isMobileLayout() {
  return window.matchMedia('(max-width: 980px)').matches;
}

function openFeeds() {
  document.body.classList.add('feeds-open');
}

function closeFeeds() {
  document.body.classList.remove('feeds-open');
}

function maskSensitiveUrl(url) {
  try {
    const parsed = new URL(url);
    const params = parsed.searchParams;
    for (const [key] of params.entries()) {
      if (/access_?key/i.test(key)) {
        params.set(key, '••••');
      }
    }
    parsed.search = params.toString() ? `?${params.toString()}` : '';
    return parsed.toString();
  } catch {
    return url.replace(/(access_?key=)[^&]+/gi, '$1••••');
  }
}

function setStatus(msg) {
  els.status.textContent = msg || '';
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`${res.status} ${res.statusText}${text ? ` - ${text}` : ''}`);
  }
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json();
  return res.text();
}

function renderFeeds() {
  const liAll = document.createElement('li');
  liAll.className = state.selectedFeedId === null ? 'feed-selected' : '';
  liAll.innerHTML = `
    <div class="feed-item">
      <div class="feed-meta">
        <div class="feed-title">All Feeds</div>
        <div class="feed-url">Unified view</div>
      </div>
      <div class="feed-actions"></div>
    </div>
  `;
  liAll.addEventListener('click', () => {
    state.selectedFeedId = null;
    state.cursor = null;
    els.itemList.innerHTML = '';
    loadItems(true);
    renderFeeds();
    if (isMobileLayout()) closeFeeds();
  });

  els.feedList.innerHTML = '';
  els.feedList.appendChild(liAll);

  for (const f of state.feeds) {
    const li = document.createElement('li');
    li.className = state.selectedFeedId === f.id ? 'feed-selected' : '';
    const title = f.title || '(untitled)';
    const last = f.last_fetch_at ? `Last: ${fmtTime(f.last_fetch_at)}` : 'Never fetched';
    const displayUrl = maskSensitiveUrl(f.url);
    li.innerHTML = `
      <div class="feed-item">
        <div class="feed-meta">
          <div class="feed-title" title="${title}">${title}</div>
          <div class="feed-url" title="${displayUrl}">${displayUrl}</div>
          <div class="feed-badge">${last}</div>
        </div>
        <div class="feed-actions">
          <button class="btn" data-action="refresh">Refresh</button>
          <button class="btn danger" data-action="delete">Delete</button>
        </div>
      </div>
    `;
    li.addEventListener('click', (e) => {
      const btn = e.target?.closest?.('button');
      if (btn) return; // handled below
      state.selectedFeedId = f.id;
      state.cursor = null;
      els.itemList.innerHTML = '';
      loadItems(true);
      renderFeeds();
      if (isMobileLayout()) closeFeeds();
    });

    li.querySelector('[data-action="refresh"]').addEventListener('click', async (e) => {
      e.stopPropagation();
      setStatus('Refreshing feed…');
      try {
        await api(`/api/feeds/${f.id}/refresh`, { method: 'POST' });
        await loadFeeds();
        await loadItems(true);
        setStatus('Refreshed.');
      } catch (err) {
        setStatus(`Refresh failed: ${err.message}`);
      }
    });

    li.querySelector('[data-action="delete"]').addEventListener('click', async (e) => {
      e.stopPropagation();
      if (!confirm('Delete this feed and all its items?')) return;
      setStatus('Deleting…');
      try {
        await api(`/api/feeds/${f.id}`, { method: 'DELETE' });
        if (state.selectedFeedId === f.id) state.selectedFeedId = null;
        state.cursor = null;
        els.itemList.innerHTML = '';
        await loadFeeds();
        await loadItems(true);
        setStatus('Deleted.');
      } catch (err) {
        setStatus(`Delete failed: ${err.message}`);
      }
    });

    els.feedList.appendChild(li);
  }
}

function renderItemsTitle() {
  const feed = state.selectedFeedId ? state.feeds.find(f => f.id === state.selectedFeedId) : null;
  const base = feed?.title ? feed.title : (state.selectedFeedId ? `Feed ${state.selectedFeedId}` : 'All Feeds');
  els.itemsTitle.textContent = `Items — ${base}`;
}

function renderItems(items, append) {
  renderItemsTitle();
  if (!append) els.itemList.innerHTML = '';

  for (const it of items) {
    const li = document.createElement('li');
    li.className = `${it.read ? 'item-read' : 'item-unread'}`;
    const title = it.title || '(no title)';
    const link = it.link || '#';
    const when = it.published_at ? fmtTime(it.published_at) : (it.fetched_at ? fmtTime(it.fetched_at) : '');
    const feedTitle = it.feed_title || '';
    li.innerHTML = `
      <div class="item-row">
        <div class="item-main">
          <div class="item-title"><a href="${link}" target="_blank" rel="noreferrer">${title}</a></div>
          <div class="item-meta">
            ${feedTitle ? `<span>${feedTitle}</span>` : ''}
            ${when ? `<span>${when}</span>` : ''}
          </div>
        </div>
        <div class="item-actions">
          <button class="btn" data-action="toggle">${it.read ? 'Unread' : 'Read'}</button>
        </div>
      </div>
    `;

    li.querySelector('[data-action="toggle"]').addEventListener('click', async () => {
      try {
        await api(`/api/items/${it.id}/read`, {
          method: 'POST',
          body: JSON.stringify({ read: !it.read }),
        });
        it.read = !it.read;
        li.className = `${it.read ? 'item-read' : 'item-unread'}`;
        li.querySelector('[data-action="toggle"]').textContent = it.read ? 'Unread' : 'Read';
      } catch (err) {
        setStatus(`Update failed: ${err.message}`);
      }
    });

    els.itemList.appendChild(li);
  }
}

async function loadFeeds() {
  const data = await api('/api/feeds');
  state.feeds = data.feeds || [];
  renderFeeds();
}

async function loadItems(reset = false) {
  if (state.loading) return;
  state.loading = true;

  if (reset) {
    state.cursor = null;
    els.itemList.innerHTML = '';
  }

  const params = new URLSearchParams();
  if (state.selectedFeedId) params.set('feed_id', String(state.selectedFeedId));
  if (state.unreadOnly) params.set('unread', '1');
  if (state.cursor) params.set('cursor', String(state.cursor));
  params.set('limit', '50');

  setStatus('Loading…');
  try {
    const data = await api(`/api/items?${params.toString()}`);
    const items = data.items || [];
    state.cursor = data.next_cursor || null;
    renderItems(items, true);

    if (items.length === 0 && reset) {
      setStatus('No items yet. Try Refresh.');
    } else {
      setStatus(state.cursor ? `Loaded ${items.length}.` : `Loaded ${items.length}. No more.`);
    }

    els.btnMore.disabled = !state.cursor;
  } catch (err) {
    setStatus(`Load failed: ${err.message}`);
  } finally {
    state.loading = false;
  }
}

async function refreshBatch() {
  setStatus('Refreshing batch…');
  try {
    await api('/api/refresh', { method: 'POST' });
    await loadFeeds();
    await loadItems(true);
    setStatus('Batch refreshed.');
  } catch (err) {
    setStatus(`Batch refresh failed: ${err.message}`);
  }
}

async function markAllRead() {
  setStatus('Marking…');
  try {
    const params = new URLSearchParams();
    if (state.selectedFeedId) params.set('feed_id', String(state.selectedFeedId));
    await api(`/api/mark_all_read?${params.toString()}`, { method: 'POST' });
    await loadItems(true);
    setStatus('Done.');
  } catch (err) {
    setStatus(`Failed: ${err.message}`);
  }
}

els.addFeedForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = els.feedUrl.value.trim();
  if (!url) return;

  setStatus('Adding feed…');
  els.addFeedForm.querySelector('button[type="submit"]').disabled = true;

  try {
    await api('/api/feeds', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
    els.feedUrl.value = '';
    await loadFeeds();
    await loadItems(true);
    setStatus('Feed added.');
  } catch (err) {
    setStatus(`Add failed: ${err.message}`);
  } finally {
    els.addFeedForm.querySelector('button[type="submit"]').disabled = false;
  }
});

els.btnRefresh.addEventListener('click', refreshBatch);
els.btnMore.addEventListener('click', () => loadItems(false));
els.btnMarkAllRead.addEventListener('click', markAllRead);
els.btnToggleFeeds.addEventListener('click', openFeeds);
els.btnCloseFeeds.addEventListener('click', closeFeeds);
els.feedsBackdrop.addEventListener('click', closeFeeds);

window.matchMedia('(max-width: 980px)').addEventListener('change', (event) => {
  if (!event.matches) closeFeeds();
});

els.unreadOnly.addEventListener('change', () => {
  state.unreadOnly = !!els.unreadOnly.checked;
  els.itemList.innerHTML = '';
  state.cursor = null;
  loadItems(true);
});

(async function init() {
  try {
    await loadFeeds();
    await loadItems(true);
    setStatus('Ready.');
  } catch (err) {
    setStatus(`Init failed: ${err.message}`);
  }
})();
