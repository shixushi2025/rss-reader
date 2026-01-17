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
  btnLogin: document.getElementById('btn-login'),
  btnAdmin: document.getElementById('btn-admin'),
  langSelect: document.getElementById('lang-select'),
  authModal: document.getElementById('auth-modal'),
  btnAuthClose: document.getElementById('btn-auth-close'),
  authForm: document.getElementById('auth-form'),
  authEmail: document.getElementById('auth-email'),
  authPassword: document.getElementById('auth-password'),
  authConfirmField: document.getElementById('auth-confirm-field'),
  authConfirm: document.getElementById('auth-confirm'),
  authTabs: document.querySelectorAll('.auth-tabs [data-mode]'),
  authGuest: document.getElementById('auth-guest'),
  authUser: document.getElementById('auth-user'),
  authUserInfo: document.getElementById('auth-user-info'),
  authStatus: document.getElementById('auth-status'),
  turnstileContainer: document.getElementById('turnstile-container'),
  btnLogout: document.getElementById('btn-logout'),
  btnGoogleLogin: document.getElementById('btn-google-login'),
};

let state = {
  feeds: [],
  selectedFeedId: null, // null means "All"
  unreadOnly: false,
  cursor: null, // for pagination
  loading: false,
  role: 'user',
  authEnabled: false,
  user: null,
  authMode: 'login',
  turnstileSiteKey: '',
  turnstileToken: '',
  turnstileWidgetId: null,
  lang: localStorage.getItem('lang') || '',
  translationsCache: new Map(),
  translateFeedTitles: false,
};

const translations = {
  zh: {
    brand: 'RSS Reader',
    feeds: '订阅源',
    refresh_batch: '批量刷新',
    login: '登录',
    admin: '管理',
    refresh: '刷新',
    delete: '删除',
    close: '关闭',
    feed_placeholder: 'https://example.com/rss.xml',
    add: '添加',
    unread_only: '仅未读',
    items: '条目',
    mark_all_read: '全部已读',
    load_more: '加载更多',
    account: '账户',
    register: '注册',
    email: '邮箱',
    email_placeholder: 'you@example.com',
    password: '密码',
    password_placeholder: '至少 8 位',
    confirm_password: '确认密码',
    confirm_password_placeholder: '重复输入密码',
    continue: '继续',
    or: '或',
    google_login: '使用 Google 登录',
    logout: '退出登录',
    footer: 'RSS-only MVP. Deployed as a Worker with static assets + D1.',
    items_prefix: '条目 — ',
    last_fetch: '最近：{time}',
    never_fetched: '从未刷新',
    all_feeds: '全部订阅源',
    unified_view: '统一视图',
    read: '已读',
    unread: '未读',
    confirm_delete_feed: '删除该订阅源及其条目？',
    status_loading: '加载中…',
    status_ready: '已就绪。',
    status_no_items: '暂无条目。可以尝试刷新。',
    status_loaded: '已加载 {count} 条。',
    status_loaded_more: '已加载 {count} 条。没有更多。',
    status_refreshing_feed: '正在刷新订阅源…',
    status_refreshed: '已刷新。',
    status_refresh_failed: '刷新失败：{error}',
    status_deleting: '正在删除…',
    status_deleted: '已删除。',
    status_delete_failed: '删除失败：{error}',
    status_adding: '正在添加订阅源…',
    status_added: '订阅源已添加。',
    status_add_failed: '添加失败：{error}',
    status_batch_refresh: '正在批量刷新…',
    status_batch_refreshed: '批量刷新完成。',
    status_batch_failed: '批量刷新失败：{error}',
    status_marking: '正在标记…',
    status_marked: '已完成。',
    status_mark_failed: '操作失败：{error}',
    status_auth_failed: '认证检查失败：{error}',
    status_admin_only: '仅管理员可操作。',
    status_login_required: '请先登录。',
    status_turnstile_required: '请先完成验证。',
    status_password_mismatch: '两次输入的密码不一致。',
    status_register_success: '注册成功。',
    status_login_success: '登录成功。',
    status_action_failed: '操作失败：{error}',
    status_logged_out: '已退出登录。',
    status_logout_failed: '退出失败：{error}',
    status_auth_disabled: '当前未开启登录功能。',
    status_update_failed: '更新失败：{error}',
    status_translating: '翻译中…',
    logged_in_as: '已登录：{email}（{role}）',
    role_admin: '管理员',
    role_user: '普通用户',
  },
  en: {
    brand: 'RSS Reader',
    feeds: 'Feeds',
    refresh_batch: 'Refresh batch',
    login: 'Login',
    admin: 'Admin',
    refresh: 'Refresh',
    delete: 'Delete',
    close: 'Close',
    feed_placeholder: 'https://example.com/rss.xml',
    add: 'Add',
    unread_only: 'Unread only',
    items: 'Items',
    mark_all_read: 'Mark all read',
    load_more: 'Load more',
    account: 'Account',
    register: 'Register',
    email: 'Email',
    email_placeholder: 'you@example.com',
    password: 'Password',
    password_placeholder: 'At least 8 characters',
    confirm_password: 'Confirm password',
    confirm_password_placeholder: 'Re-enter password',
    continue: 'Continue',
    or: 'or',
    google_login: 'Continue with Google',
    logout: 'Log out',
    footer: 'RSS-only MVP. Deployed as a Worker with static assets + D1.',
    items_prefix: 'Items — ',
    last_fetch: 'Last: {time}',
    never_fetched: 'Never fetched',
    all_feeds: 'All Feeds',
    unified_view: 'Unified view',
    read: 'Read',
    unread: 'Unread',
    confirm_delete_feed: 'Delete this feed and all its items?',
    status_loading: 'Loading…',
    status_ready: 'Ready.',
    status_no_items: 'No items yet. Try Refresh.',
    status_loaded: 'Loaded {count}.',
    status_loaded_more: 'Loaded {count}. No more.',
    status_refreshing_feed: 'Refreshing feed…',
    status_refreshed: 'Refreshed.',
    status_refresh_failed: 'Refresh failed: {error}',
    status_deleting: 'Deleting…',
    status_deleted: 'Deleted.',
    status_delete_failed: 'Delete failed: {error}',
    status_adding: 'Adding feed…',
    status_added: 'Feed added.',
    status_add_failed: 'Add failed: {error}',
    status_batch_refresh: 'Refreshing batch…',
    status_batch_refreshed: 'Batch refreshed.',
    status_batch_failed: 'Batch refresh failed: {error}',
    status_marking: 'Marking…',
    status_marked: 'Done.',
    status_mark_failed: 'Failed: {error}',
    status_auth_failed: 'Auth check failed: {error}',
    status_admin_only: 'Admin only.',
    status_login_required: 'Please sign in first.',
    status_turnstile_required: 'Please complete verification first.',
    status_password_mismatch: 'Passwords do not match.',
    status_register_success: 'Registration successful.',
    status_login_success: 'Login successful.',
    status_action_failed: 'Action failed: {error}',
    status_logged_out: 'Signed out.',
    status_logout_failed: 'Sign out failed: {error}',
    status_auth_disabled: 'Login is currently disabled.',
    status_update_failed: 'Update failed: {error}',
    status_translating: 'Translating…',
    logged_in_as: 'Signed in: {email} ({role})',
    role_admin: 'Admin',
    role_user: 'User',
  },
  ja: {
    brand: 'RSS Reader',
    feeds: 'フィード',
    refresh_batch: '一括更新',
    login: 'ログイン',
    admin: '管理',
    refresh: '更新',
    delete: '削除',
    close: '閉じる',
    feed_placeholder: 'https://example.com/rss.xml',
    add: '追加',
    unread_only: '未読のみ',
    items: '記事',
    mark_all_read: 'すべて既読',
    load_more: 'さらに読み込む',
    account: 'アカウント',
    register: '登録',
    email: 'メール',
    email_placeholder: 'you@example.com',
    password: 'パスワード',
    password_placeholder: '8文字以上',
    confirm_password: 'パスワード確認',
    confirm_password_placeholder: '再入力',
    continue: '続行',
    or: 'または',
    google_login: 'Googleでログイン',
    logout: 'ログアウト',
    footer: 'RSS-only MVP. Deployed as a Worker with static assets + D1.',
    items_prefix: '記事 — ',
    last_fetch: '最終: {time}',
    never_fetched: '未取得',
    all_feeds: 'すべてのフィード',
    unified_view: '統合ビュー',
    read: '既読',
    unread: '未読',
    confirm_delete_feed: 'このフィードと項目を削除しますか？',
    status_loading: '読み込み中…',
    status_ready: '準備完了。',
    status_no_items: 'まだ項目がありません。更新してください。',
    status_loaded: '{count} 件を読み込みました。',
    status_loaded_more: '{count} 件を読み込みました。以上です。',
    status_refreshing_feed: 'フィードを更新中…',
    status_refreshed: '更新しました。',
    status_refresh_failed: '更新失敗: {error}',
    status_deleting: '削除中…',
    status_deleted: '削除しました。',
    status_delete_failed: '削除失敗: {error}',
    status_adding: 'フィードを追加中…',
    status_added: 'フィードを追加しました。',
    status_add_failed: '追加失敗: {error}',
    status_batch_refresh: '一括更新中…',
    status_batch_refreshed: '一括更新完了。',
    status_batch_failed: '一括更新失敗: {error}',
    status_marking: '処理中…',
    status_marked: '完了。',
    status_mark_failed: '失敗: {error}',
    status_auth_failed: '認証確認に失敗: {error}',
    status_admin_only: '管理者のみ。',
    status_login_required: 'ログインしてください。',
    status_turnstile_required: '検証を完了してください。',
    status_password_mismatch: 'パスワードが一致しません。',
    status_register_success: '登録完了。',
    status_login_success: 'ログイン完了。',
    status_action_failed: '操作失敗: {error}',
    status_logged_out: 'ログアウトしました。',
    status_logout_failed: 'ログアウト失敗: {error}',
    status_auth_disabled: 'ログインは無効です。',
    status_update_failed: '更新失敗: {error}',
    status_translating: '翻訳中…',
    logged_in_as: 'ログイン中: {email}（{role}）',
    role_admin: '管理者',
    role_user: 'ユーザー',
  },
  ko: {
    brand: 'RSS Reader',
    feeds: '피드',
    refresh_batch: '일괄 새로고침',
    login: '로그인',
    admin: '관리',
    refresh: '새로고침',
    delete: '삭제',
    close: '닫기',
    feed_placeholder: 'https://example.com/rss.xml',
    add: '추가',
    unread_only: '읽지 않음만',
    items: '항목',
    mark_all_read: '모두 읽음',
    load_more: '더 보기',
    account: '계정',
    register: '회원가입',
    email: '이메일',
    email_placeholder: 'you@example.com',
    password: '비밀번호',
    password_placeholder: '8자 이상',
    confirm_password: '비밀번호 확인',
    confirm_password_placeholder: '다시 입력',
    continue: '계속',
    or: '또는',
    google_login: 'Google로 로그인',
    logout: '로그아웃',
    footer: 'RSS-only MVP. Deployed as a Worker with static assets + D1.',
    items_prefix: '항목 — ',
    last_fetch: '최근: {time}',
    never_fetched: '새로고침 기록 없음',
    all_feeds: '전체 피드',
    unified_view: '통합 보기',
    read: '읽음',
    unread: '읽지 않음',
    confirm_delete_feed: '이 피드와 항목을 삭제할까요?',
    status_loading: '불러오는 중…',
    status_ready: '준비 완료.',
    status_no_items: '아직 항목이 없습니다. 새로고침을 시도하세요.',
    status_loaded: '{count}개 로드됨.',
    status_loaded_more: '{count}개 로드됨. 더 이상 없음.',
    status_refreshing_feed: '피드 새로고침 중…',
    status_refreshed: '새로고침 완료.',
    status_refresh_failed: '새로고침 실패: {error}',
    status_deleting: '삭제 중…',
    status_deleted: '삭제됨.',
    status_delete_failed: '삭제 실패: {error}',
    status_adding: '피드 추가 중…',
    status_added: '피드가 추가되었습니다.',
    status_add_failed: '추가 실패: {error}',
    status_batch_refresh: '일괄 새로고침 중…',
    status_batch_refreshed: '일괄 새로고침 완료.',
    status_batch_failed: '일괄 새로고침 실패: {error}',
    status_marking: '처리 중…',
    status_marked: '완료.',
    status_mark_failed: '실패: {error}',
    status_auth_failed: '인증 확인 실패: {error}',
    status_admin_only: '관리자 전용.',
    status_login_required: '로그인하세요.',
    status_turnstile_required: '먼저 검증을 완료하세요.',
    status_password_mismatch: '비밀번호가 일치하지 않습니다.',
    status_register_success: '등록 성공.',
    status_login_success: '로그인 성공.',
    status_action_failed: '작업 실패: {error}',
    status_logged_out: '로그아웃되었습니다.',
    status_logout_failed: '로그아웃 실패: {error}',
    status_auth_disabled: '로그인이 비활성화되었습니다.',
    status_update_failed: '업데이트 실패: {error}',
    status_translating: '번역 중…',
    logged_in_as: '로그인: {email} ({role})',
    role_admin: '관리자',
    role_user: '사용자',
  },
};

function resolveLang() {
  if (state.lang && translations[state.lang]) return state.lang;
  const nav = (navigator.language || 'en').slice(0, 2);
  if (translations[nav]) return nav;
  return 'en';
}

function t(key) {
  const lang = resolveLang();
  return translations[lang]?.[key] || translations.en[key] || key;
}

function formatString(template, params = {}) {
  return template.replace(/\{(\w+)\}/g, (_, key) => (params[key] != null ? String(params[key]) : `{${key}}`));
}

function applyTranslations() {
  const lang = resolveLang();
  state.lang = lang;
  els.langSelect.value = lang;
  document.querySelectorAll('[data-i18n]').forEach((node) => {
    const key = node.dataset.i18n;
    if (key) node.textContent = t(key);
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((node) => {
    const key = node.dataset.i18nPlaceholder;
    if (key && node instanceof HTMLInputElement) {
      node.placeholder = t(key);
    }
  });
  renderItemsTitle();
}

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
      if (/(access_?key|key)/i.test(key)) {
        params.delete(key);
      }
    }
    parsed.search = params.toString() ? `?${params.toString()}` : '';
    return parsed.toString();
  } catch {
    return url.replace(/([?&](access_?key|key)=[^&]+)/gi, '');
  }
}

function setStatus(msg) {
  els.status.textContent = msg || '';
}

async function translateText(text) {
  if (!text || state.lang === 'en') return text;
  const target = resolveLang();
  if (!target || target === 'en') return text;
  const key = `${target}:${text}`;
  if (state.translationsCache.has(key)) return state.translationsCache.get(key);
  try {
    const data = await api('/api/translate', {
      method: 'POST',
      body: JSON.stringify({ text, target }),
    });
    const translated = data?.translated_text || text;
    state.translationsCache.set(key, translated);
    return translated;
  } catch {
    return text;
  }
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

function openAuthModal() {
  els.authModal.classList.add('is-open');
  els.authModal.setAttribute('aria-hidden', 'false');
  ensureTurnstile();
}

function closeAuthModal() {
  els.authModal.classList.remove('is-open');
  els.authModal.setAttribute('aria-hidden', 'true');
}

function isAdmin() {
  return state.role === 'admin';
}

function setAuthMode(mode) {
  state.authMode = mode;
  els.authTabs.forEach((btn) => {
    btn.classList.toggle('is-active', btn.dataset.mode === mode);
  });
  const isRegister = mode === 'register';
  els.authConfirmField.classList.toggle('is-hidden', !isRegister);
  els.authConfirm.required = isRegister;
  resetTurnstile();
}

function renderAuthStatus(message) {
  els.authStatus.textContent = message || '';
}

function resetTurnstile() {
  state.turnstileToken = '';
  if (state.turnstileWidgetId != null && window.turnstile?.reset) {
    window.turnstile.reset(state.turnstileWidgetId);
  }
}

function ensureTurnstile() {
  if (!state.turnstileSiteKey) {
    els.turnstileContainer.classList.add('is-hidden');
    return;
  }
  els.turnstileContainer.classList.remove('is-hidden');
  if (!window.turnstile || state.turnstileWidgetId != null) return;
  state.turnstileWidgetId = window.turnstile.render(els.turnstileContainer, {
    sitekey: state.turnstileSiteKey,
    callback: (token) => {
      state.turnstileToken = token;
    },
    'expired-callback': () => {
      state.turnstileToken = '';
    },
    'error-callback': () => {
      state.turnstileToken = '';
    },
  });
}

function renderAuthSections() {
  if (!state.authEnabled) {
    els.authGuest.classList.add('is-hidden');
    els.authUser.classList.add('is-hidden');
    els.authUserInfo.textContent = '';
    renderAuthStatus(t('status_auth_disabled'));
    return;
  }
  const loggedIn = !!state.user;
  els.authGuest.classList.toggle('is-hidden', loggedIn);
  els.authUser.classList.toggle('is-hidden', !loggedIn);
  if (loggedIn) {
    const roleLabel = state.role === 'admin' ? t('role_admin') : t('role_user');
    els.authUserInfo.textContent = formatString(t('logged_in_as'), { email: state.user.email, role: roleLabel });
  } else {
    els.authUserInfo.textContent = '';
  }
}

function applyAdminUI() {
  const admin = isAdmin();
  const canManageFeeds = !state.authEnabled || !!state.user || admin;
  els.btnRefresh.disabled = !admin;
  els.addFeedForm.classList.toggle('is-hidden', !canManageFeeds);
  els.feedUrl.disabled = !canManageFeeds;
  els.addFeedForm.querySelector('button[type="submit"]').disabled = !canManageFeeds;
  els.btnAdmin.classList.toggle('is-hidden', !(admin && state.authEnabled));
  els.btnLogin.classList.toggle('is-hidden', !state.authEnabled);
  renderAuthSections();
  ensureTurnstile();
}

async function refreshAuth() {
  try {
    const data = await api('/api/auth/me');
    state.role = data?.role || 'user';
    state.authEnabled = !!data?.auth_enabled;
    state.user = data?.user || null;
    state.turnstileSiteKey = data?.turnstile_site_key || '';
    state.translateFeedTitles = !!data?.translate_feed_titles;
    applyAdminUI();
    renderFeeds();
  } catch (err) {
    state.role = 'user';
    state.authEnabled = true;
    state.user = null;
    state.turnstileSiteKey = '';
    state.translateFeedTitles = false;
    applyAdminUI();
    setStatus(formatString(t('status_auth_failed'), { error: err.message }));
  }
}

function renderFeeds() {
  const liAll = document.createElement('li');
  liAll.className = state.selectedFeedId === null ? 'feed-selected' : '';
  liAll.innerHTML = `
    <div class="feed-item">
      <div class="feed-meta">
        <div class="feed-title">${t('all_feeds')}</div>
        <div class="feed-url">${t('unified_view')}</div>
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

  const admin = isAdmin();
  const canManageFeeds = !state.authEnabled || !!state.user || admin;
  for (const f of state.feeds) {
    const li = document.createElement('li');
    li.className = state.selectedFeedId === f.id ? 'feed-selected' : '';
    const title = f.title || '(untitled)';
    const last = f.last_fetch_at
      ? formatString(t('last_fetch'), { time: fmtTime(f.last_fetch_at) })
      : t('never_fetched');
    const displayUrl = maskSensitiveUrl(f.url);
    li.innerHTML = `
      <div class="feed-item">
        <div class="feed-meta">
          <div class="feed-title" title="${title}">${title}</div>
          <div class="feed-url">${displayUrl}</div>
          <div class="feed-badge">${last}</div>
        </div>
        <div class="feed-actions">
          ${admin ? `<button class="btn" data-action="refresh">${t('refresh')}</button>` : ''}
          ${canManageFeeds ? `<button class="btn danger" data-action="delete">${t('delete')}</button>` : ''}
        </div>
      </div>
    `;
    if (state.translateFeedTitles && state.lang !== 'en' && title) {
      translateText(title).then((translated) => {
        const titleEl = li.querySelector('.feed-title');
        if (titleEl) titleEl.textContent = translated;
      });
    }
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

    const refreshBtn = li.querySelector('[data-action="refresh"]');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        setStatus(t('status_refreshing_feed'));
        try {
          await api(`/api/feeds/${f.id}/refresh`, { method: 'POST' });
          await loadFeeds();
          await loadItems(true);
          setStatus(t('status_refreshed'));
        } catch (err) {
          setStatus(formatString(t('status_refresh_failed'), { error: err.message }));
        }
      });
    }

    const deleteBtn = li.querySelector('[data-action="delete"]');
    if (deleteBtn) {
      deleteBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        if (!confirm(t('confirm_delete_feed'))) return;
        setStatus(t('status_deleting'));
        try {
          await api(`/api/feeds/${f.id}`, { method: 'DELETE' });
          if (state.selectedFeedId === f.id) state.selectedFeedId = null;
          state.cursor = null;
          els.itemList.innerHTML = '';
          await loadFeeds();
          await loadItems(true);
          setStatus(t('status_deleted'));
        } catch (err) {
          setStatus(formatString(t('status_delete_failed'), { error: err.message }));
        }
      });
    }

    els.feedList.appendChild(li);
  }
}

function renderItemsTitle() {
  const feed = state.selectedFeedId ? state.feeds.find(f => f.id === state.selectedFeedId) : null;
  const base = feed?.title ? feed.title : (state.selectedFeedId ? `Feed ${state.selectedFeedId}` : 'All Feeds');
  els.itemsTitle.textContent = `${t('items_prefix')}${base}`;
  document.title = `${base} – ${t('brand')}`;
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
          <button class="btn" data-action="toggle">${it.read ? t('unread') : t('read')}</button>
        </div>
      </div>
    `;
    if (state.lang !== 'en' && title) {
      translateText(title).then((translated) => {
        const titleEl = li.querySelector('.item-title a');
        if (titleEl) titleEl.textContent = translated;
      });
    }

    li.querySelector('[data-action="toggle"]').addEventListener('click', async () => {
      try {
        await api(`/api/items/${it.id}/read`, {
          method: 'POST',
          body: JSON.stringify({ read: !it.read }),
        });
        it.read = !it.read;
        li.className = `${it.read ? 'item-read' : 'item-unread'}`;
        li.querySelector('[data-action="toggle"]').textContent = it.read ? t('unread') : t('read');
      } catch (err) {
        setStatus(formatString(t('status_update_failed'), { error: err.message }));
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

  setStatus(t('status_loading'));
  try {
    const data = await api(`/api/items?${params.toString()}`);
    const items = data.items || [];
    state.cursor = data.next_cursor || null;
    renderItems(items, true);

    if (items.length === 0 && reset) {
      setStatus(t('status_no_items'));
    } else {
      setStatus(formatString(state.cursor ? t('status_loaded') : t('status_loaded_more'), { count: items.length }));
    }

    els.btnMore.disabled = !state.cursor;
  } catch (err) {
    setStatus(formatString(t('status_action_failed'), { error: err.message }));
  } finally {
    state.loading = false;
  }
}

async function refreshBatch() {
  if (!isAdmin()) {
    setStatus(t('status_admin_only'));
    return;
  }
  setStatus(t('status_batch_refresh'));
  try {
    await api('/api/refresh', { method: 'POST' });
    await loadFeeds();
    await loadItems(true);
    setStatus(t('status_batch_refreshed'));
  } catch (err) {
    setStatus(formatString(t('status_batch_failed'), { error: err.message }));
  }
}

async function markAllRead() {
  setStatus(t('status_marking'));
  try {
    const params = new URLSearchParams();
    if (state.selectedFeedId) params.set('feed_id', String(state.selectedFeedId));
    await api(`/api/mark_all_read?${params.toString()}`, { method: 'POST' });
    await loadItems(true);
    setStatus(t('status_marked'));
  } catch (err) {
    setStatus(formatString(t('status_mark_failed'), { error: err.message }));
  }
}

els.addFeedForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const canManageFeeds = !state.authEnabled || !!state.user || isAdmin();
  if (!canManageFeeds) {
    setStatus(t('status_login_required'));
    return;
  }
  const url = els.feedUrl.value.trim();
  if (!url) return;

  setStatus(t('status_adding'));
  els.addFeedForm.querySelector('button[type="submit"]').disabled = true;

  try {
    await api('/api/feeds', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
    els.feedUrl.value = '';
    await loadFeeds();
    await loadItems(true);
    setStatus(t('status_added'));
  } catch (err) {
    setStatus(formatString(t('status_add_failed'), { error: err.message }));
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
els.btnLogin.addEventListener('click', openAuthModal);
els.btnAdmin.addEventListener('click', openAuthModal);
els.btnAuthClose.addEventListener('click', closeAuthModal);
els.authModal.addEventListener('click', (event) => {
  if (event.target === els.authModal) closeAuthModal();
});
els.langSelect.addEventListener('change', () => {
  state.lang = els.langSelect.value;
  localStorage.setItem('lang', state.lang);
  applyTranslations();
});

document.addEventListener('keydown', (event) => {
  if (event.key.toLowerCase() === 'l' && event.shiftKey && (event.ctrlKey || event.metaKey)) {
    event.preventDefault();
    openAuthModal();
  }
});

if (window.location.hash === '#login' || window.location.hash === '#admin') {
  openAuthModal();
}

els.authTabs.forEach((btn) => {
  btn.addEventListener('click', () => setAuthMode(btn.dataset.mode));
});

els.btnGoogleLogin.addEventListener('click', () => {
  window.location.href = '/api/auth/google/start';
});

els.authForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  renderAuthStatus('');
  const email = els.authEmail.value.trim();
  const password = els.authPassword.value;
  const confirm = els.authConfirm.value;
  if (state.turnstileSiteKey && !state.turnstileToken) {
    renderAuthStatus(t('status_turnstile_required'));
    return;
  }
  if (state.authMode === 'register' && password !== confirm) {
    renderAuthStatus(t('status_password_mismatch'));
    return;
  }
  try {
    const path = state.authMode === 'register' ? '/api/auth/register' : '/api/auth/login';
    await api(path, {
      method: 'POST',
      body: JSON.stringify({ email, password, turnstileToken: state.turnstileToken }),
    });
    await refreshAuth();
    renderAuthStatus(state.authMode === 'register' ? t('status_register_success') : t('status_login_success'));
    if (state.user) closeAuthModal();
  } catch (err) {
    renderAuthStatus(formatString(t('status_action_failed'), { error: err.message }));
    resetTurnstile();
  }
});

els.btnLogout.addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', { method: 'POST' });
    await refreshAuth();
    renderAuthStatus(t('status_logged_out'));
  } catch (err) {
    renderAuthStatus(formatString(t('status_logout_failed'), { error: err.message }));
  }
});

window.matchMedia('(max-width: 980px)').addEventListener('change', (event) => {
  if (!event.matches) closeFeeds();
});

els.unreadOnly.addEventListener('change', () => {
  state.unreadOnly = !!els.unreadOnly.checked;
  els.itemList.innerHTML = '';
  state.cursor = null;
  loadItems(true);
});

window.addEventListener('load', () => {
  ensureTurnstile();
});

(async function init() {
  try {
    setAuthMode(state.authMode);
    applyTranslations();
    await refreshAuth();
    await loadFeeds();
    await loadItems(true);
    setStatus(t('status_ready'));
  } catch (err) {
    setStatus(formatString(t('status_action_failed'), { error: err.message }));
  }
})();
