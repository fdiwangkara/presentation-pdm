/**
 * PDM Mentoring — Simplified PIN + Slide Viewer
 * Zero-Knowledge AES-256-GCM + PBKDF2 Web Crypto Decryption
 */

class PdmApp {
  constructor() {
    this.slides = [];
    this.currentIndex = 0;
    this.enteredPin = '';
    this.failedAttempts = 0;
    this.lockoutUntil = 0;
    this.vaultPayload = null;
    this.init();
  }

  async init() {
    this.bindEvents();
    await this.fetchVault();

    // Restore session
    const savedPin = sessionStorage.getItem('pdm_session_pin');
    if (savedPin) {
      const ok = await this.tryUnlockWithPin(savedPin, true);
      if (ok) return;
    }
  }

  async fetchVault() {
    try {
      const res = await fetch('/vault.enc.json');
      if (!res.ok) throw new Error('Vault not found');
      this.vaultPayload = await res.json();
    } catch {
      // Fallback for dev without encrypted vault
      try {
        const fb = await fetch('/slides_data.json');
        if (fb.ok) this.fallbackSlides = await fb.json();
      } catch {}
    }
  }

  bindEvents() {
    // Keypad clicks (pill buttons matching reference image)
    const keypad = document.getElementById('pinKeypad');
    if (keypad) {
      keypad.addEventListener('click', (e) => {
        const btn = e.target.closest('.pill-btn');
        if (!btn) return;
        const val = btn.dataset.val;
        if (val !== undefined) this.appendDigit(val);
        else if (btn.id === 'keyBackspace') this.backspace();
      });
    }

    // Physical & touch keyboard input
    const isTouch = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);
    const hiddenInput = document.getElementById('pinHiddenInput');
    const pinGate = document.getElementById('pinGate');
    const passcodeCard = document.getElementById('passcodeCard');
    const pinDisplay = document.getElementById('pinDisplay');

    // On touch devices (HP / tablet), disable virtual keyboard pop-up completely
    if (isTouch && hiddenInput) {
      hiddenInput.setAttribute('inputmode', 'none');
      hiddenInput.setAttribute('tabindex', '-1');
    } else if (!isTouch) {
      // Only desktop with physical keyboard focuses input
      const focusDesktop = () => {
        if (pinGate?.classList.contains('active')) hiddenInput?.focus();
      };
      pinGate?.addEventListener('click', focusDesktop);
      passcodeCard?.addEventListener('click', focusDesktop);
      pinDisplay?.addEventListener('click', focusDesktop);
    }

    if (hiddenInput) {
      hiddenInput.addEventListener('input', (e) => {
        this.enteredPin = e.target.value.replace(/\D/g, '').slice(0, 4);
        this.updateDots();
        if (this.enteredPin.length === 4) {
          this.tryUnlock();
        }
      });

      hiddenInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          this.tryUnlock();
        }
      });
    }

    // Slide navigation
    document.getElementById('btnPrev')?.addEventListener('click', () => this.prev());
    document.getElementById('btnNext')?.addEventListener('click', () => this.next());

    // Progress bar scrubbing
    const track = document.getElementById('progressTrack');
    if (track) {
      track.addEventListener('click', (e) => {
        const rect = track.getBoundingClientRect();
        const ratio = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
        this.goTo(Math.round(ratio * (this.slides.length - 1)));
      });
    }

    // Fullscreen toggle & change listeners
    document.getElementById('btnFullscreen')?.addEventListener('click', () => this.toggleFullscreen());
    document.addEventListener('fullscreenchange', () => this.handleFullscreenChange());
    document.addEventListener('webkitfullscreenchange', () => this.handleFullscreenChange());

    // Auto-hide HUD activity listener in fullscreen
    const resetHudTimer = () => {
      const viewer = document.getElementById('slideViewer');
      if (!viewer?.classList.contains('in-fullscreen')) return;
      viewer.classList.add('show-hud');
      clearTimeout(this.hudTimeout);
      this.hudTimeout = setTimeout(() => {
        viewer.classList.remove('show-hud');
      }, 2500);
    };
    window.addEventListener('mousemove', resetHudTimer);
    window.addEventListener('touchstart', resetHudTimer, { passive: true });

    // Touch swipe navigation for mobile / touch devices
    let touchStartX = 0;
    let touchStartY = 0;
    const stage = document.querySelector('.slide-stage');
    stage?.addEventListener('touchstart', (e) => {
      touchStartX = e.changedTouches[0].screenX;
      touchStartY = e.changedTouches[0].screenY;
    }, { passive: true });
    stage?.addEventListener('touchend', (e) => {
      const diffX = e.changedTouches[0].screenX - touchStartX;
      const diffY = e.changedTouches[0].screenY - touchStartY;
      if (Math.abs(diffX) > 40 && Math.abs(diffX) > Math.abs(diffY)) {
        if (diffX < 0) this.next();
        else this.prev();
      }
    }, { passive: true });

    // Lock
    document.getElementById('btnLock')?.addEventListener('click', () => this.lock());

    // Global Keyboard
    window.addEventListener('keydown', (e) => this.onKeyDown(e));
  }

  // --- PIN Input ---
  appendDigit(d) {
    if (this.enteredPin.length < 4) {
      this.enteredPin += d;
      this.updateDots();
      if (this.enteredPin.length === 4) this.tryUnlock();
    }
  }

  clearPin() {
    this.enteredPin = '';
    this.updateDots();
  }

  backspace() {
    this.enteredPin = this.enteredPin.slice(0, -1);
    this.updateDots();
  }

  updateDots() {
    const dots = document.querySelectorAll('.p-dot');
    dots.forEach((dot, i) => {
      dot.classList.toggle('filled', i < this.enteredPin.length);
    });

    const input = document.getElementById('pinHiddenInput');
    if (input && input.value !== this.enteredPin) {
      input.value = this.enteredPin;
    }
  }

  // --- Decryption & Unlock ---
  async tryUnlock() {
    const pin = this.enteredPin.trim();
    if (!pin) return;

    const now = Date.now();
    if (this.lockoutUntil > now) {
      const sec = Math.ceil((this.lockoutUntil - now) / 1000);
      this.showStatus(`Terlalu banyak percobaan. Coba lagi dalam ${sec} detik.`);
      return;
    }

    this.showStatus('Mendekripsi vault...', false);
    const ok = await this.tryUnlockWithPin(pin);

    if (!ok) {
      this.failedAttempts++;
      if (this.failedAttempts >= 5) {
        this.lockoutUntil = Date.now() + 30000;
        this.failedAttempts = 0;
        this.showStatus('Gagal 5 kali! Terkunci 30 detik.');
      } else {
        this.showStatus(`PIN salah! Sisa percobaan: ${5 - this.failedAttempts}`);
      }
      this.shakeCard();
      this.enteredPin = '';
      this.updateDots();
    }
  }

  async tryUnlockWithPin(pin, silent = false) {
    try {
      if (this.vaultPayload) {
        const data = await this.decryptVault(pin, this.vaultPayload);
        if (data) {
          this.slides = data;
          this.onSuccess(pin);
          return true;
        }
      } else if (this.fallbackSlides) {
        this.slides = this.fallbackSlides;
        this.onSuccess(pin);
        return true;
      }
    } catch {}
    return false;
  }

  async decryptVault(pin, payload) {
    const enc = new TextEncoder();
    const salt = Uint8Array.from(atob(payload.salt), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(payload.iv), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(payload.data), c => c.charCodeAt(0));

    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: payload.iterations || 200000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  onSuccess(pin) {
    sessionStorage.setItem('pdm_session_pin', pin);
    this.showStatus('PIN Benar! Membuka presentasi...', true);

    setTimeout(() => {
      document.getElementById('pinGate')?.classList.remove('active');
      const viewer = document.getElementById('slideViewer');
      if (viewer) {
        viewer.classList.remove('hidden');
        viewer.classList.add('visible');
      }
      this.goTo(0);
    }, 600);
  }

  showStatus(msg, success = false) {
    const el = document.getElementById('pinStatus');
    if (!el) return;
    el.textContent = msg;
    el.className = 'pin-status ' + (success ? 'success' : 'error');
  }

  shakeCard() {
    const card = document.querySelector('.passcode-card') || document.querySelector('.pin-card');
    if (!card) return;
    card.classList.add('shake');
    setTimeout(() => card.classList.remove('shake'), 400);
  }

  // --- Slide Navigation ---
  goTo(index) {
    if (!this.slides.length) return;
    this.currentIndex = Math.max(0, Math.min(this.slides.length - 1, index));
    const slide = this.slides[this.currentIndex];

    const img = document.getElementById('slideImg');
    const loader = document.getElementById('slideLoader');

    if (loader) loader.classList.add('active');

    if (img) {
      const newImg = new Image();
      newImg.onload = () => {
        img.src = newImg.src;
        if (loader) loader.classList.remove('active');
      };
      newImg.onerror = () => {
        if (loader) loader.classList.remove('active');
      };
      newImg.src = slide.image;
    }

    // Update counter
    const counter = document.getElementById('slideCounter');
    if (counter) counter.textContent = `${this.currentIndex + 1} / ${this.slides.length}`;

    // Update progress
    const fill = document.getElementById('progressFill');
    if (fill) fill.style.width = `${((this.currentIndex + 1) / this.slides.length) * 100}%`;

    // Preload adjacent
    this.preload(this.currentIndex + 1);
    this.preload(this.currentIndex - 1);
  }

  preload(idx) {
    if (idx < 0 || idx >= this.slides.length) return;
    const img = new Image();
    img.src = this.slides[idx].image;
  }

  prev() { this.goTo(this.currentIndex - 1); }
  next() { this.goTo(this.currentIndex + 1); }

  async toggleFullscreen() {
    const isFs = !!(document.fullscreenElement || document.webkitFullscreenElement);
    if (!isFs) {
      const el = document.documentElement;
      try {
        if (el.requestFullscreen) {
          await el.requestFullscreen();
        } else if (el.webkitRequestFullscreen) {
          await el.webkitRequestFullscreen();
        }
      } catch (err) {
        console.warn('Fullscreen request failed:', err);
      }
    } else {
      this.exitFullscreenMode();
    }
  }

  exitFullscreenMode() {
    if (document.fullscreenElement || document.webkitFullscreenElement) {
      if (document.exitFullscreen) {
        document.exitFullscreen().catch(() => {});
      } else if (document.webkitExitFullscreen) {
        document.webkitExitFullscreen();
      }
    }
  }

  handleFullscreenChange() {
    const isFs = !!(document.fullscreenElement || document.webkitFullscreenElement);
    document.body.classList.toggle('in-fullscreen', isFs);
    const viewer = document.getElementById('slideViewer');
    viewer?.classList.toggle('in-fullscreen', isFs);

    // Update fullscreen button icon and tooltip
    const btnFs = document.getElementById('btnFullscreen');
    if (btnFs) {
      btnFs.title = isFs ? 'Keluar Fullscreen (Esc / F)' : 'Fullscreen (F)';
      btnFs.innerHTML = isFs
        ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
             <path d="M8 3v3a2 2 0 0 1-2 2H3m18 0h-3a2 2 0 0 1-2-2V3m0 18v-3a2 2 0 0 1 2-2h3M3 16h3a2 2 0 0 1 2 2v3"></path>
           </svg>`
        : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
             <path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"></path>
           </svg>`;
    }

    // Trigger brief HUD reveal when entering fullscreen so user sees how to exit
    if (isFs && viewer) {
      viewer.classList.add('show-hud');
      clearTimeout(this.hudTimeout);
      this.hudTimeout = setTimeout(() => {
        viewer.classList.remove('show-hud');
      }, 2500);
    }
  }

  lock() {
    this.exitFullscreenMode();
    sessionStorage.removeItem('pdm_session_pin');
    this.slides = [];
    this.currentIndex = 0;
    this.enteredPin = '';
    this.updateDots();

    const viewer = document.getElementById('slideViewer');
    if (viewer) { viewer.classList.add('hidden'); viewer.classList.remove('visible'); }

    const gate = document.getElementById('pinGate');
    if (gate) gate.classList.add('active');

    const status = document.getElementById('pinStatus');
    if (status) { status.textContent = ''; status.className = 'pin-status'; }
  }

  onKeyDown(e) {
    // If PIN gate is active, route desktop typing directly
    const gate = document.getElementById('pinGate');
    if (gate?.classList.contains('active')) {
      if (/^[0-9]$/.test(e.key)) {
        e.preventDefault();
        this.appendDigit(e.key);
      } else if (e.key === 'Backspace') {
        e.preventDefault();
        this.backspace();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        this.tryUnlock();
      }
      return;
    }

    switch (e.key) {
      case 'ArrowRight':
      case ' ':
        e.preventDefault();
        this.next();
        break;
      case 'ArrowLeft':
        e.preventDefault();
        this.prev();
        break;
      case 'f':
      case 'F':
        this.toggleFullscreen();
        break;
      case 'Home':
        e.preventDefault();
        this.goTo(0);
        break;
      case 'End':
        e.preventDefault();
        this.goTo(this.slides.length - 1);
        break;
    }
  }
}

// Boot
new PdmApp();
