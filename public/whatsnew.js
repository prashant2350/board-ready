/* "What's new" popup. Shown once to each logged-in student per VERSION.
   To announce something new later: change `version` and the text below, then redeploy.
   Students who already saw the old version will see the new popup once. */
const WHATSNEW = {
  version: '2026-11-14',
  title: 'New on BoardReady! 🎉',
  lead: 'We added tools to help you score more in the 2027 boards.',
  items: [
    ['📊', 'Exam Insights', 'Paper pattern, chapter-wise marks and the topics that are asked again and again, subject by subject.'],
    ['⭐', 'Must-do topics', 'The chapters and topics with the highest chance of coming in your paper.'],
    ['📄', 'Papers and PYQs', 'Direct links to CBSE sample papers, marking schemes and previous year papers.'],
    ['🎯', 'My subjects', 'Pick your subjects in Account > Profile and see only what you study.']
  ],
  button: 'Explore Insights',
  link: '#insights',
  later: 'Maybe later'
};

(function () {
  const css = `.wn-back{position:fixed;inset:0;z-index:100;background:rgba(10,15,35,.55);display:grid;place-items:center;padding:16px;-webkit-backdrop-filter:blur(4px);backdrop-filter:blur(4px)}
.wn{max-width:460px;width:100%;max-height:90vh;overflow:auto;padding:24px;display:flex;flex-direction:column;gap:14px;background:var(--bg);color:var(--fg);border:1px solid var(--edge);border-radius:22px;box-shadow:var(--shadow)}
.wn h2{font-size:24px;margin:0}.wn p{margin:0;color:var(--muted)}.wn ul{list-style:none;margin:0;padding:0;display:grid;gap:10px}
.wn li{display:grid;grid-template-columns:34px 1fr;gap:10px;align-items:start;font-size:14px}.wn li i{font-style:normal;font-size:24px;line-height:1.2}.wn li b{display:block;font-family:var(--f-head)}.wn li span{color:var(--muted)}
.wn .acts{display:flex;gap:8px;flex-wrap:wrap}.wn .acts>*{flex:1;text-align:center;border:0;cursor:pointer;min-height:44px}`;
  let shown = false;
  const k = () => 'boardready.whatsnew.' + ((typeof USER !== 'undefined' && USER && USER.email) || '');
  const seen = () => { try { return localStorage.getItem(k()) === WHATSNEW.version; } catch (e) { return false; } };
  const mark = () => { try { localStorage.setItem(k(), WHATSNEW.version); } catch (e) {} };
  window.maybeWhatsNew = function () {
    if (shown || typeof USER === 'undefined' || !USER || seen()) return;
    shown = true;
    const st = document.createElement('style'); st.textContent = css; document.head.append(st);
    const esc = t => String(t).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    const back = document.createElement('div'); back.className = 'wn-back';
    back.innerHTML = `<div class="wn" role="dialog" aria-modal="true" aria-labelledby="wn-t"><h2 id="wn-t">${esc(WHATSNEW.title)}</h2><p>${esc(WHATSNEW.lead)}</p>
      <ul>${WHATSNEW.items.map(([i, t, d]) => `<li><i aria-hidden="true">${i}</i><div><b>${esc(t)}</b><span>${esc(d)}</span></div></li>`).join('')}</ul>
      <div class="acts"><button class="btn" type="button" id="wn-go">${esc(WHATSNEW.button)}</button><button class="ghost" type="button" id="wn-later">${esc(WHATSNEW.later)}</button></div></div>`;
    const prev = document.activeElement;
    const close = go => { mark(); back.remove(); document.removeEventListener('keydown', onKey); if (go) location.hash = WHATSNEW.link; else if (prev && prev.focus) prev.focus(); };
    const onKey = e => { if (e.key === 'Escape') close(false); };
    back.addEventListener('click', e => { if (e.target === back) close(false); });
    back.querySelector('#wn-go').onclick = () => close(true);
    back.querySelector('#wn-later').onclick = () => close(false);
    document.addEventListener('keydown', onKey);
    document.body.append(back); back.querySelector('#wn-go').focus();
  };
})();