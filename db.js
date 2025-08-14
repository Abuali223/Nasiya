
// DB with tx and customers
const DB_NAME = 'kirim_chiqim_db_v3';
const DB_VER = 1;
const STORE_TX = 'tx';
const STORE_CUST = 'customers';

function openDB(){
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VER);
    req.onupgradeneeded = (e)=>{
      const db = e.target.result;
      if(!db.objectStoreNames.contains(STORE_TX)){
        const tx = db.createObjectStore(STORE_TX, { keyPath: 'id', autoIncrement: true });
        tx.createIndex('date', 'date');
        tx.createIndex('type', 'type');
        tx.createIndex('payType', 'payType');
        tx.createIndex('customerId', 'customerId');
        tx.createIndex('settled', 'settled');
      }
      if(!db.objectStoreNames.contains(STORE_CUST)){
        const cs = db.createObjectStore(STORE_CUST, { keyPath: 'id', autoIncrement: true });
        cs.createIndex('name', 'name', {unique:false});
        cs.createIndex('phone', 'phone', {unique:false});
      }
    };
    req.onsuccess = ()=> resolve(req.result);
    req.onerror = ()=> reject(req.error);
  });
}

// TX API
export async function addTx(tx){
  const db = await openDB();
  return new Promise((resolve,reject)=>{
    const t = db.transaction(STORE_TX, 'readwrite');
    t.objectStore(STORE_TX).add(tx).onsuccess = e => resolve(e.target.result);
    t.onerror = ()=> reject(t.error);
  });
}
export async function listTx(){
  const db = await openDB();
  return new Promise((resolve,reject)=>{
    const t = db.transaction(STORE_TX, 'readonly');
    const r = t.objectStore(STORE_TX).getAll();
    r.onsuccess = ()=> resolve(r.result || []);
    r.onerror = ()=> reject(r.error);
  });
}
export async function deleteTx(id){
  const db = await openDB();
  return new Promise((resolve,reject)=>{
    const t = db.transaction(STORE_TX, 'readwrite');
    t.objectStore(STORE_TX).delete(id).onsuccess = ()=> resolve(true);
    t.onerror = ()=> reject(t.error);
  });
}
export async function updateTx(id, patch){
  const db = await openDB();
  const t = db.transaction(STORE_TX, 'readwrite');
  const store = t.objectStore(STORE_TX);
  const rec = await new Promise((res,rej)=>{
    const g = store.get(id);
    g.onsuccess = ()=> res(g.result);
    g.onerror = ()=> rej(g.error);
  });
  Object.assign(rec, patch);
  return new Promise((resolve,reject)=>{
    const p = store.put(rec);
    p.onsuccess = ()=> resolve(true);
    p.onerror = ()=> reject(p.error);
  });
}

// Customers
export async function addCustomer(c){
  const db = await openDB();
  return new Promise((resolve,reject)=>{
    const t = db.transaction(STORE_CUST, 'readwrite');
    t.objectStore(STORE_CUST).add(c).onsuccess = e=> resolve(e.target.result);
    t.onerror = ()=> reject(t.error);
  });
}
export async function listCustomers(){
  const db = await openDB();
  return new Promise((resolve,reject)=>{
    const t = db.transaction(STORE_CUST, 'readonly');
    const r = t.objectStore(STORE_CUST).getAll();
    r.onsuccess = ()=> resolve(r.result || []);
    r.onerror = ()=> reject(r.error);
  });
}
export async function deleteCustomer(id){
  const db = await openDB();
  return new Promise((resolve,reject)=>{
    const t = db.transaction(STORE_CUST, 'readwrite');
    t.objectStore(STORE_CUST).delete(id).onsuccess = ()=> resolve(true);
    t.onerror = ()=> reject(t.error);
  });
}
export async function clearAll(){
  const db = await openDB();
  return new Promise((resolve,reject)=>{
    const tx1 = db.transaction(STORE_TX, 'readwrite');
    const tx2 = db.transaction(STORE_CUST, 'readwrite');
    Promise.all([
      new Promise(r=> tx1.objectStore(STORE_TX).clear().onsuccess = ()=> r(true)),
      new Promise(r=> tx2.objectStore(STORE_CUST).clear().onsuccess = ()=> r(true))
    ]).then(()=> resolve(true)).catch(e=> reject(e));
  });
}
