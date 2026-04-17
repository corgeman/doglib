document$.subscribe(() => {
    document.querySelectorAll('.admonition.defn').forEach(el => {
        const title = el.querySelector('.admonition-title');
        if (!title) return;
        const name = title.textContent.trim().match(/\b(\w+)\s*[\(:\s]/)?.[1];
        if (!name) return;
        el.id = name;
        const a = document.createElement('a');
        a.href = '#' + name;
        a.className = 'headerlink';
        a.title = 'Permanent link';
        a.textContent = '¶';
        title.appendChild(a);
    });
});
