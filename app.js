'use strict';
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const now = () => new Date().toISOString();
const ST = [['todo', 'К выполнению'], ['in_progress', 'В работе'], ['done', 'Выполнено']];
const PR = [['low', 'Низкий'], ['medium', 'Средний'], ['high', 'Высокий']];
const DS = [['draft', 'Черновик'], ['review', 'На согласовании'], ['approved', 'Утверждён'], ['archived', 'Архив']];
const F = (k, l, t = 'text', r = 0, h = 0, o = null) => ({ k, l, t, r, h, o });
const RES = {
  users: { t: 'Пользователи', s: ['email', 'full_name'], f: [F('full_name', 'ФИО', 'text', 1), F('email', 'Email', 'email', 1), F('password', 'Пароль (мин. 8 символов)', 'password', 0, 1), F('role_id', 'Роль', 'select', 0, 0, 'roles'), F('active', 'Активен', 'bool')] },
  employees: { t: 'Сотрудники', s: ['full_name', 'position', 'department', 'email'], f: [F('full_name', 'ФИО', 'text', 1), F('position', 'Должность'), F('department', 'Отдел'), F('phone', 'Телефон'), F('email', 'Email', 'email'), F('hired_at', 'Дата приёма', 'date')] },
  documents: { t: 'Документы', s: ['title', 'category', 'content'], f: [F('title', 'Название', 'text', 1), F('category', 'Категория'), F('status', 'Статус', 'select', 0, 0, DS), F('content', 'Содержание', 'area', 0, 1)] },
  tasks: { t: 'Задачи', s: ['title', 'description'], f: [F('title', 'Задача', 'text', 1), F('status', 'Статус', 'select', 0, 0, ST), F('priority', 'Приоритет', 'select', 0, 0, PR), F('due_date', 'Срок', 'date'), F('assignee_id', 'Исполнитель', 'select', 0, 0, 'users'), F('description', 'Описание', 'area', 0, 1)] },
  roles: { t: 'Роли и права', s: ['name'], f: [F('name', 'Название', 'text', 1), F('permissions', 'Права (через запятую)', 'area', 1)] },
};
const NAV = [['reports', 'Отчёты', 'reports.read'], ['employees', 'Сотрудники', 'employees.read'], ['documents', 'Документы', 'documents.read'], ['tasks', 'Задачи', 'tasks.read'],
  ['users', 'Пользователи', 'users.read'], ['roles', 'Роли и права', 'roles.read'], ['settings', 'Настройки', '']];

// ---------- хранилище ----------
const KEY = 'ais_data', SK = 'ais_session'; let mem = {};
const rd = k => { try { return JSON.parse(localStorage.getItem(k)); } catch { return mem[k] ?? null; } };
const wr = (k, v) => { mem[k] = v; try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* хранилище недоступно */ } };
let D = null, S = null, page = 'reports', Q = '', menu = false, fails = 0, lock = 0;
const save = () => wr(KEY, D);
const nid = t => (D.seq[t] = (D.seq[t] || 0) + 1);
const log = (a, e, id) => { D.audit.unshift({ id: nid('audit'), user: S?.email || '—', a, e, eid: id ?? null, at: now() }); D.audit = D.audit.slice(0, 200); };
const can = p => { const x = D.roles.find(r => r.id === S.role_id)?.permissions || []; return x.includes('*') || x.includes(p); };

// ---------- пароли: PBKDF2 + соль ----------
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
async function hash(p, salt) {
  if (!crypto.subtle) throw Error('Откройте страницу через https или localhost: нужен защищённый контекст');
  salt = salt || crypto.getRandomValues(new Uint8Array(16));
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(p), 'PBKDF2', false, ['deriveBits']);
  return b64(salt) + ':' + b64(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' }, k, 256));
}
const verify = async (p, s) => (await hash(p, Uint8Array.from(atob(s.split(':')[0]), c => c.charCodeAt(0)))) === s;

async function seed(name, email, pass) {
  D = { seq: {}, roles: [], users: [], employees: [], documents: [], tasks: [], audit: [], settings: { company_name: 'Моя организация', support_email: '', notifications: 'on' } };
  const add = (n, p) => { const r = { id: nid('roles'), name: n, permissions: p }; D.roles.push(r); return r; };
  const a = add('Администратор', ['*']);
  add('Менеджер', ['employees.read', 'employees.write', 'documents.read', 'documents.write', 'tasks.read', 'tasks.write', 'reports.read']);
  add('Сотрудник', ['documents.read', 'tasks.read', 'tasks.write']);
  D.users.push({ id: nid('users'), email, full_name: name, password_hash: await hash(pass), role_id: a.id, active: true, created_at: now() });
  save();
}
async function login(e, p) {
  if (Date.now() < lock) throw Error('Слишком много попыток, подождите минуту');
  const u = D.users.find(u => u.email.toLowerCase() === e.trim().toLowerCase());
  if (!(u && u.active && await verify(p, u.password_hash))) { if (++fails >= 5) { lock = Date.now() + 60000; fails = 0; } throw Error('Неверный email или пароль'); }
  fails = 0; S = u; wr(SK, { id: u.id, exp: Date.now() + 8 * 36e5 }); log('login', 'auth'); save();
}

// ---------- данные ----------
const opts = f => f.o === 'roles' ? D.roles.map(r => [r.id, r.name]) : f.o === 'users' ? D.users.map(u => [u.id, u.full_name]) : f.o || [];
const list = (n, q) => { q = q.trim().toLowerCase(); const a = D[n].filter(r => !q || RES[n].s.some(k => String(r[k] ?? '').toLowerCase().includes(q))); return n === 'users' || n === 'roles' ? a : a.reverse(); };
async function saveRec(n, id, v) {
  if (!can(n + '.write')) throw Error('Недостаточно прав');
  const rec = {};
  for (const f of RES[n].f) {
    if (f.t === 'password') continue;
    let x = v[f.k]; if (f.t === 'bool') x = !!x; else if (typeof x === 'string') x = x.trim();
    if (x === '' || x === undefined) x = null;
    if (f.r && x == null) throw Error('Заполните поле: ' + f.l);
    if (f.o === 'roles' || f.o === 'users') x = x == null ? null : Number(x);
    rec[f.k] = x;
  }
  if (n === 'roles') {
    rec.permissions = String(rec.permissions).split(',').map(s => s.trim()).filter(Boolean);
    if (D.roles.some(r => r.id !== id && r.name === rec.name)) throw Error('Роль с таким названием уже есть');
    if (rec.permissions.includes('*') && !can('*')) throw Error('Недостаточно прав');
    if (id && D.roles.find(r => r.id === id).permissions.includes('*') && !rec.permissions.includes('*')) throw Error('Нельзя снять полный доступ с роли администратора');
  }
  if (rec.email && !/^\S+@\S+\.\S+$/.test(rec.email)) throw Error('Некорректный email');
  if (n === 'users') {
    if (D.users.some(u => u.id !== id && u.email.toLowerCase() === rec.email.toLowerCase())) throw Error('Такой email уже есть');
    if (v.password) { if (v.password.length < 8) throw Error('Пароль: минимум 8 символов'); rec.password_hash = await hash(v.password); } else if (!id) throw Error('Укажите пароль');
    if (id === S.id && !rec.active) throw Error('Нельзя деактивировать себя');
    if (rec.role_id && D.roles.find(r => r.id === rec.role_id)?.permissions.includes('*') && !can('*')) throw Error('Нельзя назначить роль администратора');
  }
  if (id) { Object.assign(D[n].find(r => r.id === id), rec); log('update', n, id); }
  else { rec.id = nid(n); rec.created_at = now(); if (n === 'documents') rec.author_id = S.id; D[n].push(rec); log('create', n, rec.id); }
  save();
}
function remove(n, id) {
  if (!can(n + '.write')) throw Error('Недостаточно прав');
  if (n === 'users' && id === S.id) throw Error('Нельзя удалить себя');
  if (n === 'roles' && D.users.some(u => u.role_id === id)) throw Error('Роль назначена пользователям');
  D[n] = D[n].filter(r => r.id !== id);
  if (n === 'users') { D.tasks.forEach(t => { if (t.assignee_id === id) t.assignee_id = null; }); D.documents.forEach(d => { if (d.author_id === id) d.author_id = null; }); }
  log('delete', n, id); save();
}
const dl = (name, text, type) => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); };
function csv(n) {
  const rs = D[n]; if (!rs.length) return alert('Нет данных');
  const ks = Object.keys(rs[0]).filter(k => k !== 'password_hash');
  const q = v => { let s = Array.isArray(v) ? v.join('; ') : String(v ?? ''); if (/^[=+\-@]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
  dl(n + '.csv', '\ufeff' + [ks.join(','), ...rs.map(r => ks.map(k => q(r[k])).join(','))].join('\n'), 'text/csv');
}

// ---------- представления ----------
const lbl = (f, v) => v == null ? '—' : f.t === 'bool' ? (v ? '✓' : '✗') : f.t === 'date' ? String(v).slice(0, 10) : f.t === 'select' ? (opts(f).find(o => String(o[0]) === String(v))?.[1] ?? v) : Array.isArray(v) ? v.join(', ') : v;
const rowsHtml = n => {
  const w = can(n + '.write'), cols = RES[n].f.filter(f => !f.h);
  return list(n, Q).map(r => `<tr>${cols.map(f => `<td data-l="${esc(f.l)}">${esc(lbl(f, r[f.k]))}</td>`).join('')}${w ? `<td class="act"><button data-a="edit" data-id="${r.id}">Изменить</button><button class="dng" data-a="del" data-id="${r.id}">Удалить</button></td>` : ''}</tr>`).join('') || '<tr><td colspan="9">Ничего не найдено</td></tr>';
};
const viewRes = n => `<div class="bar"><h2>${RES[n].t}</h2><input id="q" class="grow" placeholder="Поиск…" value="${esc(Q)}">${can(n + '.write') ? '<button class="btn" data-a="add">+ Добавить</button>' : ''}</div>
  <table><thead><tr>${RES[n].f.filter(f => !f.h).map(f => `<th>${esc(f.l)}</th>`).join('')}${can(n + '.write') ? '<th></th>' : ''}</tr></thead><tbody id="tb">${rowsHtml(n)}</tbody></table>`;
function viewReports() {
  const cnt = (a, k) => { const m = {}; a.forEach(x => { const v = x[k] || '—'; m[v] = (m[v] || 0) + 1; }); return Object.entries(m); };
  const bars = (t, e, lab) => { const m = Math.max(1, ...e.map(x => x[1])); return `<div class="card"><h3>${t}</h3>${e.map(([k, n]) => `<div class="br"><span>${esc(lab?.find(o => o[0] === k)?.[1] ?? k)}</span><i style="width:${n / m * 100}%"></i><b>${n}</b></div>`).join('') || '<small>Нет данных</small>'}</div>`; };
  const T = [['Пользователи', D.users.length], ['Сотрудники', D.employees.length], ['Документы', D.documents.length], ['Открытые задачи', D.tasks.filter(t => t.status !== 'done').length]];
  return `<h2>Отчёты</h2><div class="grid">${T.map(([l, n]) => `<div class="card"><h3>${l}</h3><div class="big">${n}</div></div>`).join('')}</div>
  <div class="grid">${bars('Задачи по статусам', cnt(D.tasks, 'status'), ST)}${bars('Документы по статусам', cnt(D.documents, 'status'), DS)}${bars('Сотрудники по отделам', cnt(D.employees, 'department'))}</div>
  <div class="card"><h3>Экспорт в CSV</h3><div class="bar">${['employees', 'documents', 'tasks', 'users'].filter(n => can(n + '.read')).map(n => `<button data-a="csv" data-n="${n}">${RES[n].t}</button>`).join('')}</div></div>
  <h3>Журнал действий</h3><table><thead><tr><th>Время</th><th>Пользователь</th><th>Действие</th><th>Объект</th></tr></thead><tbody>${D.audit.slice(0, 20).map(a => `<tr><td data-l="Время">${new Date(a.at).toLocaleString('ru-RU')}</td><td data-l="Пользователь">${esc(a.user)}</td><td data-l="Действие">${esc(a.a)}</td><td data-l="Объект">${esc(a.e)}${a.eid ? ' #' + a.eid : ''}</td></tr>`).join('')}</tbody></table>`;
}
function viewSettings() {
  const s = D.settings, dis = can('settings.write') ? '' : 'disabled';
  return `<h2>Настройки</h2><form id="set" class="fm"><label>Название организации<input name="company_name" value="${esc(s.company_name)}" ${dis}></label>
  <label>Email поддержки<input type="email" name="support_email" value="${esc(s.support_email)}" ${dis}></label>
  <label>Уведомления<select name="notifications" ${dis}><option value="on"${s.notifications === 'on' ? ' selected' : ''}>Включены</option><option value="off"${s.notifications === 'off' ? ' selected' : ''}>Выключены</option></select></label>
  <span class="err"></span><span id="msg"></span>${dis ? '' : '<button class="btn">Сохранить</button>'}</form>
  ${can('*') ? '<div class="card" style="margin-top:14px"><h3>Данные</h3><div class="bar"><button data-a="backup">Резервная копия (JSON)</button><button class="dng" data-a="reset">Сбросить все данные</button></div></div>' : ''}`;
}
const authView = setup => `<div class="mid"><form class="login" id="${setup ? 'sup' : 'lf'}"><h2>${setup ? 'Первый запуск: создайте администратора' : 'Вход в систему'}</h2>
  ${setup ? '<input name="n" placeholder="ФИО" required>' : ''}<input type="email" name="e" placeholder="Email" required autocomplete="username">
  <input type="password" name="p" placeholder="Пароль${setup ? ' (мин. 8 символов)' : ''}" required minlength="${setup ? 8 : 1}" autocomplete="${setup ? 'new-password' : 'current-password'}">
  <span class="err"></span><button class="btn">${setup ? 'Создать и войти' : 'Войти'}</button></form></div>`;
function render() {
  const app = $('#app');
  if (!D) return void (app.innerHTML = authView(true));
  if (!S) return void (app.innerHTML = authView(false));
  const nav = NAV.filter(n => !n[2] || can(n[2]));
  if (!nav.some(n => n[0] === page)) page = nav[0][0];
  app.innerHTML = `<div class="app"><aside class="side${menu ? ' open' : ''}"><h1>${esc(D.settings.company_name)}</h1>${nav.map(n => `<button class="${page === n[0] ? 'on' : ''}" data-a="nav" data-p="${n[0]}">${n[1]}</button>`).join('')}</aside>
  <main><header><button class="burger" data-a="menu" aria-label="Меню">☰</button><form class="grow" id="sf"><input name="q" placeholder="Глобальный поиск…"></form><span class="who">${esc(S.full_name)}</span><button data-a="logout">Выйти</button></header>
  <div id="hits"></div><div class="content">${page === 'reports' ? viewReports() : page === 'settings' ? viewSettings() : viewRes(page)}</div></main></div>`;
}
function openForm(n, id) {
  const rec = id ? D[n].find(r => r.id === id) : null;
  const inp = f => {
    const v = rec ? rec[f.k] : f.t === 'bool' ? true : f.t === 'select' && Array.isArray(f.o) ? f.o[0][0] : '';
    if (f.t === 'bool') return `<input type="checkbox" name="${f.k}"${v ? ' checked' : ''}>`;
    if (f.t === 'select') return `<select name="${f.k}">${Array.isArray(f.o) ? '' : '<option value="">—</option>'}${opts(f).map(o => `<option value="${esc(o[0])}"${String(o[0]) === String(v ?? '') ? ' selected' : ''}>${esc(o[1])}</option>`).join('')}</select>`;
    if (f.t === 'area') return `<textarea name="${f.k}" rows="4">${esc(Array.isArray(v) ? v.join(', ') : v)}</textarea>`;
    const val = f.t === 'password' ? '' : f.t === 'date' ? String(v ?? '').slice(0, 10) : v ?? '';
    return `<input type="${f.t}" name="${f.k}" value="${esc(val)}" ${f.t === 'password' ? (id ? '' : 'required') + ' minlength="8" autocomplete="new-password"' : f.r ? 'required' : ''}>`;
  };
  $('#m').innerHTML = `<form id="mf" class="fm" data-n="${n}" data-id="${id}"><h3>${id ? 'Изменить' : 'Добавить'}</h3>${RES[n].f.map(f => `<label>${esc(f.l)}${inp(f)}</label>`).join('')}
  ${n === 'roles' ? '<small>Права: <code>*</code> (всё) или <code>раздел.read</code>, <code>раздел.write</code> для users, roles, employees, documents, tasks, reports, settings.</small>' : ''}
  <span class="err"></span><div class="row"><button type="button" data-a="cancel">Отмена</button><button class="btn">Сохранить</button></div></form>`;
  $('#m').showModal();
}

// ---------- события ----------
document.addEventListener('click', e => {
  const d = $('#m'); if (e.target === d) return d.close();
  const b = e.target.closest('[data-a]'); if (!b) return;
  const a = b.dataset.a, id = +b.dataset.id;
  try {
    if (a === 'nav') { page = b.dataset.p; Q = ''; menu = false; render(); }
    else if (a === 'goto') { page = b.dataset.p; Q = b.dataset.q; render(); }
    else if (a === 'menu') { menu = !menu; render(); }
    else if (a === 'logout') { wr(SK, null); S = null; render(); }
    else if (a === 'add') openForm(page, 0);
    else if (a === 'edit') openForm(page, id);
    else if (a === 'del') { if (confirm('Удалить запись?')) { remove(page, id); render(); } }
    else if (a === 'cancel') d.close();
    else if (a === 'closehits') $('#hits').innerHTML = '';
    else if (a === 'csv') csv(b.dataset.n);
    else if (a === 'backup') dl('backup.json', JSON.stringify(D, null, 1), 'application/json');
    else if (a === 'reset') { if (confirm('Удалить ВСЕ данные без возможности восстановления?')) { try { localStorage.removeItem(KEY); localStorage.removeItem(SK); } catch { } mem = {}; D = S = null; render(); } }
  } catch (x) { alert(x.message); }
});
document.addEventListener('input', e => { if (e.target.id === 'q') { Q = e.target.value; $('#tb').innerHTML = rowsHtml(page); } });
document.addEventListener('submit', async e => {
  e.preventDefault(); const f = e.target, fd = new FormData(f), err = f.querySelector('.err');
  try {
    if (f.id === 'sup') { await seed(fd.get('n').trim(), fd.get('e').trim().toLowerCase(), fd.get('p')); await login(fd.get('e'), fd.get('p')); render(); }
    else if (f.id === 'lf') { await login(fd.get('e'), fd.get('p')); render(); }
    else if (f.id === 'sf') {
      const q = fd.get('q').trim(); if (!q) return;
      const h = Object.keys(RES).filter(n => can(n + '.read')).flatMap(n => list(n, q).slice(0, 5).map(r => { const t = r[RES[n].s[0]]; return `<button data-a="goto" data-p="${n}" data-q="${esc(t)}">${RES[n].t}: ${esc(t)}</button>`; }));
      $('#hits').innerHTML = `<div class="hits">${h.join('') || '<p>Ничего не найдено</p>'}<button data-a="closehits">Закрыть</button></div>`;
    }
    else if (f.id === 'mf') { await saveRec(f.dataset.n, +f.dataset.id, Object.fromEntries(RES[f.dataset.n].f.map(x => [x.k, x.t === 'bool' ? fd.has(x.k) : fd.get(x.k)]))); $('#m').close(); render(); }
    else if (f.id === 'set') {
      if (!can('settings.write')) throw Error('Недостаточно прав');
      for (const k of ['company_name', 'support_email', 'notifications']) D.settings[k] = String(fd.get(k) ?? '').slice(0, 200);
      log('update', 'settings'); save(); render(); $('#msg').textContent = 'Сохранено';
    }
  } catch (x) { if (err) err.textContent = x.message; }
});

D = rd(KEY);
if (D) { const s = rd(SK); if (s && s.exp > Date.now()) S = D.users.find(u => u.id === s.id && u.active) || null; }
render();
