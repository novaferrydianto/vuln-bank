/* =========================================================
   ✅ SECURE HELPERS
========================================================= */

function authHeaders(extra = {}) {
    const token = localStorage.getItem('jwt_token');
    return token ? { ...extra, Authorization: `Bearer ${token}` } : extra;
}

function clear(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
}

function el(tag, { text, className } = {}) {
    const e = document.createElement(tag);
    if (className) e.className = className;
    if (text !== undefined) e.textContent = text;
    return e;
}

function setMessage(msg, color = 'black') {
    const m = document.getElementById('message');
    if (!m) return;
    m.textContent = msg;
    m.style.color = color;
}

/* =========================================================
   ✅ INITIALIZATION
========================================================= */

document.addEventListener('DOMContentLoaded', () => {
    const dateEl = document.getElementById('current-date');
    if (dateEl) {
        dateEl.textContent = new Date().toLocaleDateString('en-US', {
            weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
        });
    }

    if (!localStorage.getItem('jwt_token')) {
        location.replace('/login');
        return;
    }

    document.getElementById('transferForm')?.addEventListener('submit', handleTransfer);
    document.getElementById('loanForm')?.addEventListener('submit', handleLoanRequest);
    document.getElementById('profileUploadForm')?.addEventListener('submit', handleProfileUpload);
    document.getElementById('profileUrlButton')?.addEventListener('click', handleProfileUrlImport);
    document.getElementById('createCardForm')?.addEventListener('submit', handleCreateCard);
    document.getElementById('payBillForm')?.addEventListener('submit', handleBillPayment);

    fetchTransactions();
    fetchVirtualCards();
    loadBillCategories();
    loadPaymentHistory();

    window.addEventListener('scroll', handleScroll);
});

/* =========================================================
   ✅ NAVIGATION
========================================================= */

function handleScroll() {
    document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));

    document.querySelectorAll('.dashboard-section').forEach(sec => {
        if (window.scrollY >= sec.offsetTop - 200) {
            const l = document.querySelector(`.nav-link[href="#${sec.id}"]`);
            if (l) l.classList.add('active');
        }
    });
}

/* =========================================================
   ✅ TRANSFER
========================================================= */

async function handleTransfer(e) {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));

    try {
        const r = await fetch('/transfer', {
            method: 'POST',
            headers: authHeaders({ 'Content-Type': 'application/json' }),
            body: JSON.stringify(data)
        });
        const j = await r.json();

        if (j.status === 'success') {
            setMessage(j.message, 'green');
            document.getElementById('balance').textContent = j.new_balance;
            fetchTransactions();
            e.target.reset();
        } else {
            setMessage(j.message, 'red');
        }
    } catch {
        setMessage('Transfer failed', 'red');
    }
}

/* =========================================================
   ✅ TRANSACTIONS (XSS SAFE)
========================================================= */

async function fetchTransactions() {
    const list = document.getElementById('transaction-list');
    clear(list);

    try {
        const acc = document.getElementById('account-number').textContent;
        const r = await fetch(`/transactions/${acc}`, { headers: authHeaders() });
        const j = await r.json();

        if (!j.status || !j.transactions.length) {
            list.appendChild(el('p', { text: 'No transactions found' }));
            return;
        }

        j.transactions.forEach(t => {
            const out = t.from_account === acc;
            const item = el('div', { className: `transaction-item ${out ? 'sent' : 'received'}` });

            const d = el('div', { className: 'transaction-details' });
            d.appendChild(el('div', {
                className: 'transaction-account',
                text: out ? `To: ${t.to_account}` : `From: ${t.from_account}`
            }));
            d.appendChild(el('div', { className: 'transaction-date', text: t.timestamp }));
            if (t.description) d.appendChild(el('div', {
                className: 'transaction-description',
                text: t.description
            }));

            const amt = el('div', {
                className: `transaction-amount ${out ? 'sent' : 'received'}`,
                text: `${out ? '-' : '+'}$${Math.abs(t.amount)}`
            });

            item.append(d, amt);
            list.appendChild(item);
        });
    } catch {
        list.appendChild(el('p', { text: 'Error loading transactions' }));
    }
}

/* =========================================================
   ✅ VIRTUAL CARDS
========================================================= */

let virtualCards = [];

async function fetchVirtualCards() {
    try {
        const r = await fetch('/api/virtual-cards', { headers: authHeaders() });
        const j = await r.json();
        if (j.status === 'success') {
            virtualCards = j.cards;
            renderVirtualCards();
        }
    } catch {}
}

function renderVirtualCards() {
    const c = document.getElementById('virtual-cards-list');
    clear(c);

    if (!virtualCards.length) {
        c.appendChild(el('p', { text: 'No virtual cards found' }));
        return;
    }

    virtualCards.forEach(card => {
        const v = el('div', { className: `virtual-card ${card.is_frozen ? 'frozen' : ''}` });
        v.appendChild(el('div', { className: 'card-type', text: card.card_type.toUpperCase() }));
        v.appendChild(el('div', { className: 'card-number', text: formatCardNumber(card.card_number) }));

        const act = el('div', { className: 'card-actions' });
        [['Freeze', () => toggleCardFreeze(card.id)],
         ['Details', () => showCardDetails(card.id)],
         ['History', () => showTransactionHistory(card.id)],
         ['Update Limit', () => showUpdateLimit(card.id)]
        ].forEach(([l, fn]) => {
            const b = document.createElement('button');
            b.textContent = card.is_frozen && l === 'Freeze' ? 'Unfreeze' : l;
            b.addEventListener('click', fn);
            act.appendChild(b);
        });

        v.appendChild(act);
        c.appendChild(v);
    });
}

function formatCardNumber(n) {
    return n.match(/.{1,4}/g).join(' ');
}

/* =========================================================
   ✅ BILL CATEGORIES & PAYMENTS
========================================================= */

async function loadBillCategories() {
    const s = document.getElementById('billCategory');
    clear(s);
    s.appendChild(new Option('Select Category', ''));

    try {
        const r = await fetch('/api/bill-categories');
        const j = await r.json();
        if (j.status === 'success') {
            j.categories.forEach(c => s.appendChild(new Option(c.name, c.id)));
        }
    } catch {}
}

async function loadPaymentHistory() {
    const c = document.getElementById('bill-payments-list');
    clear(c);

    try {
        const r = await fetch('/api/bill-payments/history', { headers: authHeaders() });
        const j = await r.json();
        if (!j.status || !j.payments.length) {
            c.appendChild(el('p', { text: 'No bill payments found' }));
            return;
        }

        j.payments.forEach(p => {
            const i = el('div', { className: 'payment-item' });
            i.appendChild(el('div', { text: `$${p.amount}` }));
            i.appendChild(el('div', { text: p.status }));
            i.appendChild(el('div', { text: `Biller: ${p.biller_name}` }));
            if (p.description) i.appendChild(el('div', { text: p.description }));
            c.appendChild(i);
        });
    } catch {}
}

/* =========================================================
   ✅ LOGOUT
========================================================= */

function logout() {
    localStorage.removeItem('jwt_token');
    location.replace('/login');
}
