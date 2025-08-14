
import {
  addTx, listTx, deleteTx, updateTx, clearAll,
  addCustomer, listCustomers, deleteCustomer
} from './db.js';

const $  = (q, el=document)=> el.querySelector(q);
const $$ = (q, el=document)=> Array.from(el.querySelectorAll(q));

function fmt(n){ try{ return new Intl.NumberFormat('uz-UZ',{maximumFractionDigits:0}).format(n) }catch{ return String(n) } }
function todayStr(){ const d = new Date(); const z = d.getTimezoneOffset()*60000; return new Date(Date.now()-z).toISOString().slice(0,10); }
function toDateOnly(str){ if(!str) return ''; const d = new Date(str); const z = d.getTimezoneOffset()*60000; return new Date(d.getTime()-z).toISOString().slice(0,10); }

// ---------- Customers ----------
async function refreshCustomers(selectOnly=false){
  const data = await listCustomers();
  data.sort((a,b)=> a.name.localeCompare(b.name));
  const sel = $('#customerSelect'); const fsel = $('#fCustomer');
  const keepVal = sel?.value || '';
  if(sel){
    sel.innerHTML = `<option value="">— Mijoz (ixtiyoriy) —</option>` + data.map(c=> `<option value="${c.id}">${c.name}</option>`).join('');
    sel.value = keepVal;
  }
  if(fsel){
    const keepF = fsel.value || '';
    fsel.innerHTML = `<option value="">Mijoz: barchasi</option>` + data.map(c=> `<option value="${c.id}">${c.name}</option>`).join('');
    fsel.value = keepF;
  }
  if(selectOnly) return;
  const list = $('#custList');
  if(list){
    list.innerHTML = '';
    const tpl = $('#custTpl');
    data.forEach(c=>{
      const node = tpl.content.cloneNode(true);
      node.querySelector('.title').textContent = c.name;
      node.querySelector('.sub').textContent = c.phone ? c.phone : '—';
      const row = node.querySelector('.item');
      row.dataset.id = c.id;
      list.appendChild(node);
    });
  }
}

function bindCustomerUI(){
  $('#custForm').addEventListener('submit', async (e)=>{
    e.preventDefault();
    const form = Object.fromEntries(new FormData(e.target).entries());
    if(!form.name?.trim()){ alert('Mijoz ismi kiriting.'); return; }
    await addCustomer({name: form.name.trim(), phone: (form.phone||'').trim()});
    e.target.reset();
    refreshCustomers();
  });
  $('#custList').addEventListener('click', async (e)=>{
    const btn = e.target.closest('button[data-action="delete"]');
    if(!btn) return;
    const row = e.target.closest('.item');
    const id = Number(row?.dataset?.id);
    if(confirm('Mijozni o‘chirishni tasdiqlaysizmi?')){
      await deleteCustomer(id);
      refreshCustomers();
    }
  });
  $('#quickAddCust').addEventListener('click', async ()=>{
    const name = prompt('Mijoz ismi:');
    if(!name) return;
    const phone = prompt('Telefon (+998...):') || '';
    const id = await addCustomer({name: name.trim(), phone: phone.trim()});
    await refreshCustomers(true);
    $('#customerSelect').value = String(id);
  });
}

// ---------- Transactions ----------
function matchFilters(row){
  const from = $('#fFrom').value;
  const to   = $('#fTo').value;
  const t    = $('#fType').value;
  const p    = $('#fPay').value;
  const c    = $('#fCustomer').value;
  const q    = $('#fQ').value.trim().toLowerCase();

  if(from && row.date < from) return false;
  if(to && row.date > to) return false;
  if(t && row.type !== t) return false;
  if(p && row.payType !== p) return false;
  if(c && String(row.customerId||'') !== c) return false;
  if(q){
    const hay = [row.category||'', row.note||'', row.customerName||''].join(' ').toLowerCase();
    if(!hay.includes(q)) return false;
  }
  return true;
}

function renderTx(rows){
  const list = $('#txList'); if(!list) return;
  list.innerHTML = '';
  const tpl = $('#txTpl');
  rows.sort((a,b)=> a.date.localeCompare(b.date) || (a.id-b.id));
  rows.forEach(r=>{
    const node = tpl.content.cloneNode(true);
    node.querySelector('.item').dataset.id = r.id;
    node.querySelector('.title').textContent = `${r.type==='kirim'?'Kirim':'Chiqim'} • ${r.category||'—'}`;
    const bits = [toDateOnly(r.date)];
    if(r.customerName) bits.push(r.customerName + (r.customerPhone? ` (${r.customerPhone})` : ''));
    bits.push(r.payType==='nasiya' ? `Nasiya (${r.settled==='ha'?'qoplangan':'qoplanmagan'})` : r.payType);
    if(r.note) bits.push(r.note);
    node.querySelector('.sub').textContent = bits.join(' • ');
    node.querySelector('.amt').textContent = (r.type==='chiqim'?'-':'+') + fmt(r.amount);
    list.appendChild(node);
  });
}

function calcStats(rows){
  let income=0, expense=0, debt=0;
  for(const r of rows){
    if(r.type==='kirim') income += Number(r.amount)||0;
    if(r.type==='chiqim') expense += Number(r.amount)||0;
    if(r.payType==='nasiya' && r.settled!=='ha' && r.type==='kirim'){
      debt += Number(r.amount)||0;
    }
  }
  $('#sumIncome').textContent = fmt(income);
  $('#sumExpense').textContent = fmt(expense);
  $('#sumProfit').textContent = fmt(income-expense);
  $('#sumDebt').textContent = fmt(debt);
}

// ---------- Debts per customer ----------
function computeDebts(rows){
  // Outstanding receivables: only kirim+nasiya where settled!='ha'
  const map = new Map();
  for(const r of rows){
    if(r.type==='kirim' && r.payType==='nasiya' && r.settled!=='ha'){
      const key = String(r.customerId||'0'); // 0 -> "Noma’lum mijoz"
      if(!map.has(key)) map.set(key, { total:0, count:0, name: r.customerName||'Noma’lum', phone: r.customerPhone||'' , id: r.customerId||null });
      const obj = map.get(key);
      obj.total += Number(r.amount)||0;
      obj.count += 1;
    }
  }
  return Array.from(map.values()).sort((a,b)=> b.total - a.total);
}

function renderDebtList(debts){
  const list = $('#debtList'); if(!list) return;
  list.innerHTML = '';
  const tpl = $('#debtTpl');
  debts.forEach(d=>{
    const node = tpl.content.cloneNode(true);
    node.querySelector('.title').textContent = d.name;
    node.querySelector('.sub').textContent = (d.phone||'—') + ' • yozuvlar: ' + d.count;
    node.querySelector('.amt').textContent = fmt(d.total);
    const row = node.querySelector('.item');
    row.dataset.customerId = d.id? String(d.id) : '';
    list.appendChild(node);
  });
}

function exportDebtCsv(debts){
  const header = ['mijoz','telefon','qarzdorlik','yozuvlar_soni'];
  const rows = [header.join(',')];
  for(const d of debts){
    rows.push([JSON.stringify(d.name||''), JSON.stringify(d.phone||''), d.total, d.count].join(','));
  }
  const blob = new Blob([rows.join('\\n')], {type:'text/csv;charset=utf-8;'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'qarzdorlik.csv'; a.click();
  URL.revokeObjectURL(url);
}

async function refresh(){
  const [tx, customers] = await Promise.all([listTx(), listCustomers()]);
  const map = new Map(customers.map(c=> [String(c.id), c]));
  tx.forEach(r=>{
    if(r.customerId){
      const c = map.get(String(r.customerId));
      if(c){ r.customerName = c.name; r.customerPhone = c.phone; }
    }
  });
  const filt = tx.filter(matchFilters);
  renderTx(filt);
  calcStats(filt);

  const debts = computeDebts(filt);
  renderDebtList(debts);
  // bind "Ko'rish" buttons to set filter by customer
  $('#debtList')?.addEventListener('click', (e)=>{
    const btn = e.target.closest('button[data-action="filter"]'); if(!btn) return;
    const item = e.target.closest('.item');
    const cid = item?.dataset?.customerId || '';
    const fSel = $('#fCustomer'); if(fSel){ fSel.value = cid; }
    document.querySelector('[data-tab="tx"]').click();
    // trigger refresh to apply filter
    setTimeout(refresh, 0);
  });

  $('#exportDebtCsvBtn')?.addEventListener('click', ()=> exportDebtCsv(debts), { once: true });
}

function bindTxUI(){
  $('input[name="date"]').value = todayStr();
  const paySel = $('select[name="payType"]');
  const nasiyaBlock = $('.nasiya-only');
  const syncNasiya = ()=>{
    if(paySel.value==='nasiya') nasiyaBlock.classList.remove('hidden');
    else nasiyaBlock.classList.add('hidden');
  };
  paySel.addEventListener('change', syncNasiya); syncNasiya();

  $('#txForm').addEventListener('submit', async (e)=>{
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target).entries());
    d.amount = Number(d.amount||0);
    if(!d.date) d.date = todayStr();
    if(d.payType!=='nasiya') d.settled = 'yoq';
    if(d.customerId==='') d.customerId = null;
    await addTx(d);
    e.target.reset();
    $('input[name="date"]').value = todayStr();
    syncNasiya();
    refresh();
  });

  $('#txList').addEventListener('click', async (e)=>{
    const btn = e.target.closest('button[data-action]'); if(!btn) return;
    const id = Number(e.target.closest('.item')?.dataset?.id);
    if(btn.dataset.action==='delete'){
      if(confirm('Yozuvni o‘chirishni tasdiqlaysizmi?')){
        await deleteTx(id);
        refresh();
      }
    }else if(btn.dataset.action==='toggle-settle'){
      const all = await listTx();
      const r = all.find(x=> x.id===id);
      if(!r) return;
      const next = r.settled==='ha' ? 'yoq' : 'ha';
      await updateTx(id, { settled: next });
      refresh();
    }
  });

  ['fFrom','fTo','fType','fPay','fCustomer','fQ'].forEach(id=>{
    document.getElementById(id).addEventListener('input', refresh);
  });

  $('#exportCsvBtn').addEventListener('click', async ()=>{
    const [tx, customers] = await Promise.all([listTx(), listCustomers()]);
    const map = new Map(customers.map(c=> [String(c.id), c]));
    tx.forEach(r=>{
      if(r.customerId){
        const c = map.get(String(r.customerId));
        if(c){ r.customerName = c.name; r.customerPhone = c.phone; }
      }
    });
    const filt = tx.filter(matchFilters);
    const header = ['id','sana','turi','tolov','miqdor','kategoriya','izoh','nasiya_qoplandi','mijoz','telefon'];
    const rows = [header.join(',')];
    for(const r of filt){
      rows.push([
        r.id, toDateOnly(r.date), r.type, r.payType, r.amount,
        JSON.stringify(r.category||''), JSON.stringify(r.note||''),
        r.settled||'yoq', JSON.stringify(r.customerName||''), JSON.stringify(r.customerPhone||'')
      ].join(','));
    }
    const blob = new Blob([rows.join('\\n')], {type:'text/csv;charset=utf-8;'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'hisobot.csv'; a.click();
    URL.revokeObjectURL(url);
  });

  $('#clearAllBtn').addEventListener('click', async ()=>{
    if(confirm('Barcha ma’lumot o‘chiriladi. Davom etamizmi?')){
      await clearAll();
      refresh();
      refreshCustomers();
    }
  });
}

async function main(){
  bindCustomerUI();
  bindTxUI();
  await refreshCustomers();
  await refresh();
}
document.addEventListener('DOMContentLoaded', main);
