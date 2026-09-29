// Shared helpers for the staff pages.
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cap = s => s ? s[0].toUpperCase() + s.slice(1) : '';
const fmtDateTime = iso => iso ? new Date(iso).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }) : '—';

function toast(msg) {
  const t = $('toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove('show'), 2600);
}

async function api(url, opts = {}) {
  const res = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...opts });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) { location.href = '/login'; throw new Error('Signed out'); }
  if (data.error === 'password_change_required') { location.href = '/account'; throw new Error(data.error); }
  if (!res.ok) throw new Error(data.error || 'Something went wrong');
  return data;
}

async function signOut() {
  await fetch('/api/logout', { method: 'POST' });
  location.href = '/login';
}

// Fills <header id="topbar"> and resolves with the signed-in staff member.
async function initStaffPage(active) {
  const { user } = await api('/api/me');
  const link = (href, label, key) =>
    `<a href="${href}" class="${active === key ? 'current' : ''}">${label}</a>`;
  $('topbar').innerHTML = `
    <div class="brand"><span class="crest">DC</span> Licensing Team</div>
    <button class="menu-toggle" aria-expanded="false" aria-controls="nav"
      onclick="this.setAttribute('aria-expanded', $('nav').classList.toggle('open'))">Menu</button>
    <nav class="nav" id="nav">
      ${user.must_change_password ? '' : link('/admin', 'Drivers', 'drivers') + link('/admin/vehicles', 'Vehicles', 'vehicles')}
      ${user.role === 'admin' && !user.must_change_password ? link('/admin/staff', 'Staff', 'staff') : ''}
      <a href="/" target="_blank">Public registers ↗</a>
      <span class="who">${link('/account', esc(user.full_name), 'account')} <span class="role">${cap(user.role)}</span></span>
      <button class="link" onclick="signOut()">Sign out</button>
    </nav>`;
  return user;
}
