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

    // Fullscreen toggle & change listeners (Game mode)
    document.getElementById('btnFullscreen')?.addEventListener('click', () => this.toggleFullscreen());
    document.getElementById('btnFsExit')?.addEventListener('click', () => this.toggleFullscreen());
    document.addEventListener('fullscreenchange', () => this.handleFullscreenChange());
    document.addEventListener('webkitfullscreenchange', () => this.handleFullscreenChange());

    // When phone is naturally held horizontal, exit virtual rotation
    window.addEventListener('resize', () => {
      if (window.innerWidth > window.innerHeight) {
        const viewer = document.getElementById('slideViewer');
        viewer?.classList.remove('game-mode-landscape');
        document.body.classList.remove('in-game-landscape');
      }
    });

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
    const viewer = document.getElementById('slideViewer');
    const isVirtual = viewer?.classList.contains('game-mode-landscape');
    const isNativeFs = !!(document.fullscreenElement || document.webkitFullscreenElement);

    if (isVirtual || isNativeFs) {
      this.exitFullscreenMode();
      return;
    }

    const isPortrait = window.innerHeight > window.innerWidth;
    let orientationLocked = false;

    // 1. Try native fullscreen (Android / Desktop)
    const el = document.documentElement;
    try {
      if (el.requestFullscreen) {
        await el.requestFullscreen();
      } else if (el.webkitRequestFullscreen) {
        await el.webkitRequestFullscreen();
      }
    } catch (err) {}

    // 2. Try Screen Orientation API (Android Chrome / modern web apps)
    if (screen.orientation && screen.orientation.lock) {
      try {
        await screen.orientation.lock('landscape');
        orientationLocked = true;
      } catch (err) {}
    }

    // 3. Universal Fallback for iOS / Mobile portrait where orientation lock API is restricted:
    // Rotate into game-mode landscape via CSS transform
    if (isPortrait && !orientationLocked) {
      viewer?.classList.add('game-mode-landscape');
      document.body.classList.add('in-game-landscape');
    }
  }

  exitFullscreenMode() {
    const viewer = document.getElementById('slideViewer');
    viewer?.classList.remove('game-mode-landscape');
    document.body.classList.remove('in-game-landscape');

    if (screen.orientation && screen.orientation.unlock) {
      try { screen.orientation.unlock(); } catch (err) {}
    }

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
    document.getElementById('slideViewer')?.classList.toggle('in-fullscreen', isFs);

    if (!isFs) {
      const viewer = document.getElementById('slideViewer');
      viewer?.classList.remove('game-mode-landscape');
      document.body.classList.remove('in-game-landscape');
      if (screen.orientation && screen.orientation.unlock) {
        try { screen.orientation.unlock(); } catch (err) {}
      }
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
