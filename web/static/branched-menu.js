/* BranchedMenu - Vanilla JS Implementation from React Bits */
(function (global) {
  'use strict';

  const PAD = 6;
  const MARK = 16;

  const ICONS = {
    rocket: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/><path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6.05 11a22.35 22.35 0 0 1-3.95 2z"/><path d="M9 12H4s.5-3 3-4"/><path d="M12 9V4s3 .5 4 3"/></svg>',
    layers: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>',
    chat: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>',
    chart: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>',
    shield: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    search: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    bug: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="8" height="14" x="8" y="6" rx="4"/><path d="m19 7-3 2"/><path d="m5 7 3 2"/><path d="m19 19-3-2"/><path d="m5 19 3-2"/><path d="M20 13h-4"/><path d="M4 13h4"/><path d="m10 4 1 2"/><path d="m14 4-1 2"/></svg>',
    lock: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
    download: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
    settings: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    cursor: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m3 3 7.07 16.97 2.51-7.39 7.39-2.51L3 3z"/><path d="m13 13 6 6"/></svg>',
    upload: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>'
  };

  function toSet(open) {
    if (Array.isArray(open)) return new Set(open);
    if (typeof open === 'number' && open >= 0) return new Set([open]);
    return new Set();
  }

  class BranchedMenu {
    constructor(container, options = {}) {
      this.container = container;
      this.options = Object.assign({
        items: [],
        defaultOpen: [0, 1],
        defaultActive: 'range',
        color: 'var(--text, #f5f5f5)',
        accentColor: 'var(--accent, #7C9BFF)',
        lineColor: 'var(--line, #3f3f46)',
        width: 240,
        rowHeight: 36,
        indent: 40,
        trunk: 14,
        radius: 10,
        lineWidth: 1.5,
        fontSize: 14,
        drawDuration: 400,
        foldDuration: 300,
        onSelect: null,
        onToggle: null
      }, options);

      this.open = toSet(this.options.defaultOpen);
      this.active = this.options.defaultActive || this.findFirstActive();
      this.heads = [];
      this.reachPaths = new Map(); // value -> { el, len }

      this.render();
      this.setupObserver();
      this.placeMarker(false);
    }

    findFirstActive() {
      for (let i = 0; i < this.options.items.length; i++) {
        const item = this.options.items[i];
        if (item.children && item.children.length && this.open.has(i)) {
          return item.children[0].value;
        }
      }
      return '';
    }

    render() {
      const opt = this.options;
      const nav = document.createElement('nav');
      nav.className = `branched-menu ${opt.className || ''}`.trim();
      nav.style.setProperty('--bm-w', `${opt.width}px`);
      nav.style.setProperty('--bm-ink', opt.color);
      nav.style.setProperty('--bm-accent', opt.accentColor);
      nav.style.setProperty('--bm-line', opt.lineColor);
      nav.style.setProperty('--bm-font', `${opt.fontSize}px`);
      nav.style.setProperty('--bm-row', `${opt.rowHeight}px`);
      nav.style.setProperty('--bm-indent', `${opt.indent}px`);
      nav.style.setProperty('--bm-line-w', opt.lineWidth);
      nav.style.setProperty('--bm-draw', `${opt.drawDuration}ms`);
      nav.style.setProperty('--bm-fold', `${opt.foldDuration}ms`);

      const marker = document.createElement('span');
      marker.className = 'branched-menu__marker';
      marker.setAttribute('aria-hidden', 'true');
      this.marker = marker;
      nav.appendChild(marker);

      const r = Math.min(opt.radius, opt.rowHeight / 2 - 2);
      const endX = opt.indent - 8;
      const rowY = k => PAD + k * opt.rowHeight + opt.rowHeight / 2;
      const branch = k => `M ${opt.trunk} ${rowY(k) - r} A ${r} ${r} 0 0 0 ${opt.trunk + r} ${rowY(k)} H ${endX}`;
      const reach = k => `M ${opt.trunk} 0 V ${rowY(k) - r} A ${r} ${r} 0 0 0 ${opt.trunk + r} ${rowY(k)} H ${endX}`;
      const length = k => rowY(k) - r + (Math.PI * r) / 2 + (endX - opt.trunk - r);

      opt.items.forEach((item, i) => {
        const kids = item.children;
        const isOpen = kids ? this.open.has(i) : false;
        const leafValue = item.value ?? item.label;
        const leafActive = !kids && leafValue === this.active;
        const bodyH = kids ? PAD * 2 + kids.length * opt.rowHeight : 0;

        const section = document.createElement('div');
        section.className = 'branched-menu__section';
        if (isOpen) section.setAttribute('data-open', '');
        section.dataset.sectionIndex = i;

        const head = document.createElement('button');
        head.type = 'button';
        head.className = 'branched-menu__head';
        if (kids) head.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        if (leafActive) {
          head.setAttribute('aria-current', 'true');
          head.setAttribute('data-active', '');
        }
        head.textContent = item.label;
        head.onclick = () => {
          if (kids) this.toggle(i);
          else this.select(leafValue, item);
        };
        this.heads[i] = head;
        section.appendChild(head);

        if (kids) {
          const body = document.createElement('div');
          body.className = 'branched-menu__body';

          const fold = document.createElement('div');
          fold.className = 'branched-menu__fold';

          const tree = document.createElement('div');
          tree.className = 'branched-menu__tree';
          tree.style.height = `${bodyH}px`;

          const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
          svg.setAttribute('class', 'branched-menu__lines');
          svg.setAttribute('width', opt.indent);
          svg.setAttribute('height', bodyH);
          svg.setAttribute('aria-hidden', 'true');

          const basePath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
          basePath.setAttribute('class', 'branched-menu__base');
          basePath.setAttribute('d', `M ${opt.trunk} 0 V ${rowY(kids.length - 1) - r}`);
          svg.appendChild(basePath);

          kids.forEach((kid, k) => {
            const b = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            b.setAttribute('class', 'branched-menu__base');
            b.setAttribute('d', branch(k));
            svg.appendChild(b);
          });

          kids.forEach((kid, k) => {
            const len = length(k);
            const reachPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            reachPath.setAttribute('class', 'branched-menu__reach');
            reachPath.setAttribute('d', reach(k));
            reachPath.style.strokeDasharray = len;
            reachPath.style.strokeDashoffset = kid.value === this.active ? 0 : len;
            svg.appendChild(reachPath);
            this.reachPaths.set(kid.value, { el: reachPath, len });
          });

          tree.appendChild(svg);

          kids.forEach(kid => {
            const itemBtn = document.createElement('button');
            itemBtn.type = 'button';
            itemBtn.className = 'branched-menu__item';
            itemBtn.dataset.value = kid.value;
            if (kid.value === this.active) {
              itemBtn.setAttribute('aria-current', 'true');
              itemBtn.setAttribute('data-active', '');
            }
            itemBtn.tabIndex = isOpen ? 0 : -1;
            itemBtn.onclick = () => this.select(kid.value, kid, true);

            if (kid.icon) {
              const iconSpan = document.createElement('span');
              iconSpan.className = 'branched-menu__icon';
              iconSpan.setAttribute('aria-hidden', 'true');
              iconSpan.innerHTML = typeof kid.icon === 'string' && ICONS[kid.icon] ? ICONS[kid.icon] : kid.icon;
              itemBtn.appendChild(iconSpan);
            }

            const labelSpan = document.createElement('span');
            labelSpan.className = 'branched-menu__label';
            labelSpan.textContent = kid.label;
            itemBtn.appendChild(labelSpan);

            tree.appendChild(itemBtn);
          });

          fold.appendChild(tree);
          body.appendChild(fold);
          section.appendChild(body);
        }

        nav.appendChild(section);
      });

      this.nav = nav;
      this.container.innerHTML = '';
      this.container.appendChild(nav);
    }

    setupObserver() {
      let first = true;
      this.ro = new ResizeObserver(() => {
        if (first) {
          first = false;
          return;
        }
        this.placeMarker(false);
      });
      this.ro.observe(this.nav);
    }

    getActiveSection() {
      return this.options.items.findIndex(it => it.children && it.children.some(kid => kid.value === this.active));
    }

    placeMarker(glide = true) {
      if (!this.marker) return;
      const activeSection = this.getActiveSection();
      const markerShown = activeSection >= 0 && this.open.has(activeSection);
      const el = this.heads[activeSection];

      if (!glide) this.marker.style.transition = 'none';

      if (markerShown && el) {
        this.marker.style.top = `${el.offsetTop + (el.offsetHeight - MARK) / 2}px`;
        this.marker.setAttribute('data-on', '');
      } else {
        this.marker.removeAttribute('data-on');
      }

      if (!glide) {
        void this.marker.offsetHeight;
        this.marker.style.transition = '';
      }
    }

    toggle(index) {
      const section = this.nav.querySelector(`[data-section-index="${index}"]`);
      if (!section) return;

      const isOpen = this.open.has(index);
      if (isOpen) {
        this.open.delete(index);
        section.removeAttribute('data-open');
        this.heads[index]?.setAttribute('aria-expanded', 'false');
        section.querySelectorAll('.branched-menu__item').forEach(b => b.tabIndex = -1);
      } else {
        this.open.add(index);
        section.setAttribute('data-open', '');
        this.heads[index]?.setAttribute('aria-expanded', 'true');
        section.querySelectorAll('.branched-menu__item').forEach(b => b.tabIndex = 0);
      }

      this.placeMarker(true);
      if (typeof this.options.onToggle === 'function') {
        this.options.onToggle(index, !isOpen);
      }
    }

    select(value, item, triggerCallback = true) {
      this.active = value;

      // Update reach lines
      this.reachPaths.forEach(({ el, len }, val) => {
        el.style.strokeDashoffset = val === value ? 0 : len;
      });

      // Update items active state
      this.nav.querySelectorAll('.branched-menu__item').forEach(btn => {
        const isAct = btn.dataset.value === value;
        if (isAct) {
          btn.setAttribute('aria-current', 'true');
          btn.setAttribute('data-active', '');
        } else {
          btn.removeAttribute('aria-current');
          btn.removeAttribute('data-active');
        }
      });

      // Update leaf heads active state
      this.heads.forEach(head => {
        head.removeAttribute('aria-current');
        head.removeAttribute('data-active');
      });

      this.placeMarker(true);

      if (triggerCallback && typeof this.options.onSelect === 'function') {
        this.options.onSelect(value, item);
      }
    }

    setActive(value) {
      const activeSec = this.options.items.findIndex(it => it.children && it.children.some(kid => kid.value === value));
      if (activeSec >= 0 && !this.open.has(activeSec)) {
        this.toggle(activeSec);
      }
      this.select(value, null, false);
    }

    destroy() {
      this.ro?.disconnect();
      this.nav?.remove();
    }
  }

  global.BranchedMenu = BranchedMenu;
})(window);
