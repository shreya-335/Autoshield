// content.js
// AutoShield Content Script
// Runs in the context of the web page being inspected.
// Extracts security-relevant and compliance-relevant data
// then sends it to the side panel via the background service worker.

(function () {
  'use strict';

  // ─── Listen for extraction request from background ─────────────────
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'extractPageData') {
      try {
        const data = extractAll();
        chrome.runtime.sendMessage({
          source: 'autoshield-content',
          type: 'pageDataExtracted',
          data
        });
        sendResponse({ ok: true });
      } catch (e) {
        chrome.runtime.sendMessage({
          source: 'autoshield-content',
          type: 'extractionError',
          error: e.message
        });
        sendResponse({ ok: false, error: e.message });
      }
    }
    return true;
  });

  // ─── Main Extraction Orchestrator ─────────────────────────────────
  function extractAll() {
    return {
      url: window.location.href,
      origin: window.location.origin,
      title: document.title,
      timestamp: Date.now(),

      // Security data
      security: {
        inlineScripts: extractInlineScripts(),
        externalScripts: extractExternalScripts(),
        forms: extractForms(),
        mixedContent: detectMixedContent(),
        dangerousPatterns: detectDangerousPatterns(),
        metaTags: extractSecurityMetaTags(),
        iframes: extractIframes(),
        storageUsage: checkStorageForSensitiveData(),
        eventHandlers: detectInlineEventHandlers(),
        openRedirects: detectOpenRedirectParams(),
      },

      // Compliance / copyright data
      compliance: {
        images: extractImages(),
        videos: extractVideos(),
        audios: extractAudios(),
        fonts: extractFonts(),
        externalStylesheets: extractExternalStylesheets(),
        textBlocks: extractTextBlocks(),
        iframeEmbeds: extractIframeEmbeds(),
        licenseIndicators: detectLicenseIndicators(),
      }
    };
  }

  // ════════════════════════════════════════════════════════════════════
  // SECURITY EXTRACTORS
  // ════════════════════════════════════════════════════════════════════

  function extractInlineScripts() {
    const scripts = [];
    document.querySelectorAll('script:not([src])').forEach((s, i) => {
      const content = s.textContent.trim();
      if (!content) { return; }
      scripts.push({
        index: i,
        // Send first 500 chars for analysis — enough for RAG context
        snippet: content.slice(0, 500),
        length: content.length,
        hasEval: /\beval\s*\(/.test(content),
        hasDocumentWrite: /document\.write\s*\(/.test(content),
        hasInnerHTML: /\.innerHTML\s*=/.test(content),
        hasDangerousUrl: /javascript\s*:/i.test(content),
        hasBase64: /atob\s*\(|btoa\s*\(/.test(content),
        hasFetch: /fetch\s*\(|XMLHttpRequest/.test(content),
      });
    });
    return scripts;
  }

  function extractExternalScripts() {
    const scripts = [];
    document.querySelectorAll('script[src]').forEach((s) => {
      const src = s.getAttribute('src') || '';
      const resolved = resolveUrl(src);
      scripts.push({
        src: resolved,
        isExternal: isExternalUrl(resolved),
        isMixedContent: isHttpOnHttpsPage(resolved),
        hasSRI: !!s.getAttribute('integrity'),
        async: s.hasAttribute('async'),
        defer: s.hasAttribute('defer'),
        crossOrigin: s.getAttribute('crossorigin') || null,
      });
    });
    return scripts;
  }

  function extractForms() {
    const forms = [];
    document.querySelectorAll('form').forEach((f, i) => {
      const action = f.getAttribute('action') || '';
      const method = (f.getAttribute('method') || 'get').toLowerCase();
      const inputs = Array.from(f.querySelectorAll('input')).map((inp) => ({
        type: inp.type,
        name: inp.name,
        hasAutocomplete: inp.hasAttribute('autocomplete'),
        autocompleteValue: inp.getAttribute('autocomplete'),
      }));
      const hasPasswordField = inputs.some((i) => i.type === 'password');
      forms.push({
        index: i,
        action: resolveUrl(action),
        method,
        isHttpAction: isHttpOnHttpsPage(resolveUrl(action)),
        hasPasswordField,
        hasCSRFToken: detectCSRFToken(f),
        inputCount: inputs.length,
        inputs: inputs.slice(0, 10),
      });
    });
    return forms;
  }

  function detectMixedContent() {
    const mixed = [];
    const attrs = ['src', 'href', 'action', 'data'];
    document.querySelectorAll('*').forEach((el) => {
      attrs.forEach((attr) => {
        const val = el.getAttribute(attr);
        if (val && isHttpOnHttpsPage(val)) {
          mixed.push({
            tag: el.tagName.toLowerCase(),
            attr,
            url: val,
          });
        }
      });
    });
    return mixed.slice(0, 20);
  }

  function detectDangerousPatterns() {
    const patterns = [];
    const bodyText = document.body ? document.body.innerHTML : '';

    // Check for common dangerous patterns in page source
    const checks = [
      { name: 'eval()', regex: /\beval\s*\(/g },
      { name: 'document.write()', regex: /document\.write\s*\(/g },
      { name: 'innerHTML assignment', regex: /\.innerHTML\s*=/g },
      { name: 'javascript: protocol', regex: /javascript\s*:/gi },
      { name: 'data: URI', regex: /data:text\/html/gi },
      { name: 'base64 encoded script', regex: /atob\s*\(/g },
      { name: 'onmessage handler', regex: /window\.onmessage/g },
      { name: 'postMessage without origin check', regex: /postMessage\([^)]*\)/g },
    ];

    checks.forEach((c) => {
      const matches = bodyText.match(c.regex);
      if (matches && matches.length > 0) {
        patterns.push({ pattern: c.name, count: matches.length });
      }
    });

    return patterns;
  }

  function extractSecurityMetaTags() {
    const meta = {};
    document.querySelectorAll('meta').forEach((m) => {
      const httpEquiv = (m.getAttribute('http-equiv') || '').toLowerCase();
      const name = (m.getAttribute('name') || '').toLowerCase();
      const content = m.getAttribute('content') || '';

      if (httpEquiv === 'content-security-policy') { meta.csp = content; }
      if (httpEquiv === 'x-frame-options') { meta.xFrameOptions = content; }
      if (httpEquiv === 'referrer-policy' || name === 'referrer') { meta.referrerPolicy = content; }
      if (name === 'robots') { meta.robots = content; }
    });

    // Check response headers via performance API if available
    try {
      const perf = performance.getEntriesByType('navigation')[0];
      if (perf) {
        meta.transferSize = perf.transferSize;
        meta.domContentLoaded = Math.round(perf.domContentLoadedEventEnd);
      }
    } catch (_) {}

    return meta;
  }

  function extractIframes() {
    return Array.from(document.querySelectorAll('iframe')).map((f) => ({
      src: f.getAttribute('src') || '',
      sandbox: f.getAttribute('sandbox') || null,
      allow: f.getAttribute('allow') || null,
      isExternal: isExternalUrl(f.getAttribute('src') || ''),
      isMixedContent: isHttpOnHttpsPage(f.getAttribute('src') || ''),
    })).slice(0, 10);
  }

  function checkStorageForSensitiveData() {
    const results = { localStorage: [], sessionStorage: [] };
    const sensitivePatterns = /token|password|secret|key|auth|session|credit|card|ssn|api/i;

    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (sensitivePatterns.test(k)) {
          results.localStorage.push({ key: k, valueLength: (localStorage.getItem(k) || '').length });
        }
      }
    } catch (_) {}

    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        if (sensitivePatterns.test(k)) {
          results.sessionStorage.push({ key: k, valueLength: (sessionStorage.getItem(k) || '').length });
        }
      }
    } catch (_) {}

    return results;
  }

  function detectInlineEventHandlers() {
    const handlers = [];
    const eventAttrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onsubmit', 'onchange', 'onfocus'];
    eventAttrs.forEach((attr) => {
      const els = document.querySelectorAll(`[${attr}]`);
      if (els.length > 0) {
        handlers.push({ event: attr, count: els.length });
      }
    });
    return handlers;
  }

  function detectOpenRedirectParams() {
    const params = new URLSearchParams(window.location.search);
    const redirectParams = ['redirect', 'url', 'next', 'return', 'returnUrl', 'goto', 'target', 'dest', 'destination'];
    const found = [];
    redirectParams.forEach((p) => {
      if (params.has(p)) {
        found.push({ param: p, value: params.get(p) });
      }
    });
    return found;
  }

  function detectCSRFToken(form) {
    const csrfNames = ['csrf', '_token', 'csrfmiddlewaretoken', 'authenticity_token', '_csrf'];
    return csrfNames.some((name) =>
      form.querySelector(`input[name="${name}"], input[name*="csrf" i]`) !== null
    );
  }

  // ════════════════════════════════════════════════════════════════════
  // COMPLIANCE EXTRACTORS
  // ════════════════════════════════════════════════════════════════════

  function extractImages() {
    const images = [];
    document.querySelectorAll('img').forEach((img) => {
      const src = img.getAttribute('src') || img.currentSrc || '';
      if (!src || src.startsWith('data:')) { return; }
      const resolved = resolveUrl(src);
      images.push({
        src: resolved,
        alt: img.getAttribute('alt') || '',
        width: img.naturalWidth || img.width,
        height: img.naturalHeight || img.height,
        isExternal: isExternalUrl(resolved),
        domain: extractDomain(resolved),
        hasTitle: !!img.getAttribute('title'),
        // CSS background images are not captured here — see below
        fromCSSBackground: false,
      });
    });

    // Also find CSS background images
    document.querySelectorAll('*').forEach((el) => {
      try {
        const bg = window.getComputedStyle(el).backgroundImage;
        if (bg && bg !== 'none' && bg.includes('url(')) {
          const match = bg.match(/url\(["']?([^"')]+)["']?\)/);
          if (match && match[1] && !match[1].startsWith('data:')) {
            const resolved = resolveUrl(match[1]);
            images.push({
              src: resolved,
              alt: '',
              isExternal: isExternalUrl(resolved),
              domain: extractDomain(resolved),
              fromCSSBackground: true,
            });
          }
        }
      } catch (_) {}
    });

    // Deduplicate by src
    const seen = new Set();
    return images.filter((img) => {
      if (seen.has(img.src)) { return false; }
      seen.add(img.src);
      return true;
    }).slice(0, 50);
  }

  function extractVideos() {
    return Array.from(document.querySelectorAll('video, video source')).map((el) => {
      const src = el.getAttribute('src') || el.currentSrc || '';
      const resolved = resolveUrl(src);
      return {
        src: resolved,
        type: el.getAttribute('type') || '',
        isExternal: isExternalUrl(resolved),
        domain: extractDomain(resolved),
        hasControls: el.hasAttribute('controls'),
        autoplay: el.hasAttribute('autoplay'),
      };
    }).filter((v) => v.src).slice(0, 20);
  }

  function extractAudios() {
    return Array.from(document.querySelectorAll('audio, audio source')).map((el) => {
      const src = el.getAttribute('src') || '';
      const resolved = resolveUrl(src);
      return {
        src: resolved,
        type: el.getAttribute('type') || '',
        isExternal: isExternalUrl(resolved),
        domain: extractDomain(resolved),
      };
    }).filter((a) => a.src).slice(0, 20);
  }

  function extractFonts() {
    const fonts = [];
    const seen = new Set();

    // From <link> tags (Google Fonts etc.)
    document.querySelectorAll('link[rel="stylesheet"], link[rel="preload"]').forEach((link) => {
      const href = link.getAttribute('href') || '';
      if (href && (href.includes('font') || href.includes('fonts.google') || href.includes('typekit'))) {
        if (!seen.has(href)) {
          seen.add(href);
          fonts.push({ src: href, via: 'link', domain: extractDomain(href) });
        }
      }
    });

    // From @font-face in stylesheets (best effort)
    try {
      Array.from(document.styleSheets).forEach((sheet) => {
        try {
          Array.from(sheet.cssRules || []).forEach((rule) => {
            if (rule.type === CSSRule.FONT_FACE_RULE) {
              const src = rule.style.getPropertyValue('src');
              if (src) {
                fonts.push({ src: src.slice(0, 200), via: 'font-face', domain: extractDomain(src) });
              }
            }
          });
        } catch (_) {} // cross-origin stylesheets will throw
      });
    } catch (_) {}

    return fonts.slice(0, 20);
  }

  function extractExternalStylesheets() {
    return Array.from(document.querySelectorAll('link[rel="stylesheet"]')).map((link) => {
      const href = link.getAttribute('href') || '';
      const resolved = resolveUrl(href);
      return {
        href: resolved,
        isExternal: isExternalUrl(resolved),
        domain: extractDomain(resolved),
        hasSRI: !!link.getAttribute('integrity'),
      };
    }).filter((s) => s.href).slice(0, 20);
  }

  function extractTextBlocks() {
    // Extract meaningful text paragraphs for potential duplicate/copyright check
    const blocks = [];
    const selectors = ['p', 'article', 'blockquote', '.content', 'main', 'section'];
    selectors.forEach((sel) => {
      document.querySelectorAll(sel).forEach((el) => {
        const text = el.innerText?.trim();
        if (text && text.length > 100 && text.length < 5000) {
          blocks.push({ text: text.slice(0, 500), selector: sel, wordCount: text.split(/\s+/).length });
        }
      });
    });
    return blocks.slice(0, 10);
  }

  function extractIframeEmbeds() {
    // Specifically capture embed iframes (YouTube, Vimeo, etc.) for compliance
    return Array.from(document.querySelectorAll('iframe')).map((f) => {
      const src = f.getAttribute('src') || '';
      return {
        src,
        domain: extractDomain(src),
        isYouTube: src.includes('youtube.com') || src.includes('youtu.be'),
        isVimeo: src.includes('vimeo.com'),
        isSpotify: src.includes('spotify.com'),
        isSoundCloud: src.includes('soundcloud.com'),
        isOtherEmbed: isExternalUrl(src),
      };
    }).filter((f) => f.src).slice(0, 10);
  }

  function detectLicenseIndicators() {
    const indicators = {
      hasCreativeCommons: false,
      hasCopyrightNotice: false,
      copyrightText: '',
      hasAttributionLinks: false,
      unsplashImages: 0,
      pixabayImages: 0,
      pexelsImages: 0,
      shutterstockImages: 0,
      gettyImages: 0,
      adobeStockImages: 0,
    };

    const bodyText = document.body?.innerText?.toLowerCase() || '';
    const bodyHTML = document.body?.innerHTML?.toLowerCase() || '';

    indicators.hasCreativeCommons = bodyText.includes('creative commons') || bodyHTML.includes('creativecommons.org');
    indicators.hasCopyrightNotice = /©|&copy;|copyright\s+\d{4}/i.test(bodyHTML);

    const copyrightMatch = document.body?.innerText?.match(/©[^<\n]{1,80}|Copyright [^<\n]{1,80}/i);
    if (copyrightMatch) { indicators.copyrightText = copyrightMatch[0]; }

    indicators.hasAttributionLinks = !!document.querySelector('a[href*="unsplash.com"], a[href*="pixabay.com"], a[href*="pexels.com"]');

    // Count images from known stock sites
    document.querySelectorAll('img').forEach((img) => {
      const src = (img.getAttribute('src') || '').toLowerCase();
      if (src.includes('unsplash')) { indicators.unsplashImages++; }
      if (src.includes('pixabay')) { indicators.pixabayImages++; }
      if (src.includes('pexels')) { indicators.pexelsImages++; }
      if (src.includes('shutterstock')) { indicators.shutterstockImages++; }
      if (src.includes('gettyimages') || src.includes('istockphoto')) { indicators.gettyImages++; }
      if (src.includes('adobe') && src.includes('stock')) { indicators.adobeStockImages++; }
    });

    return indicators;
  }

  // ════════════════════════════════════════════════════════════════════
  // UTILITY FUNCTIONS
  // ════════════════════════════════════════════════════════════════════

  function resolveUrl(url) {
    if (!url) { return ''; }
    try {
      return new URL(url, window.location.href).href;
    } catch (_) {
      return url;
    }
  }

  function isExternalUrl(url) {
    if (!url) { return false; }
    try {
      return new URL(url).origin !== window.location.origin;
    } catch (_) {
      return false;
    }
  }

  function isHttpOnHttpsPage(url) {
    if (!url || window.location.protocol !== 'https:') { return false; }
    try {
      return new URL(url, window.location.href).protocol === 'http:';
    } catch (_) {
      return false;
    }
  }

  function extractDomain(url) {
    try {
      return new URL(url).hostname;
    } catch (_) {
      return '';
    }
  }

})();