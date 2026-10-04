/**
 * ============================================================
 * Virtual Cryptography Laboratory - Unified Client Controller
 * Controls Toolbar, Tab Navigation, Read Aloud, Zoom, Share & Modals
 * ============================================================
 */

(() => {
  'use strict';

  // Available tabs order mapping
  const TABS_ORDER = [
    'aim',
    'theory',
    'procedure',
    'simulation',
    'quiz',
    'references',
    'feedback'
  ];

  // DOM Elements
  const tabButtons = document.querySelectorAll('.resource-nav-btn[data-tab]');
  const tabPanels = document.querySelectorAll('.tab-content-panel[data-tab-panel]');
  const pageCounter = document.getElementById('pageCounterText');
  const prevTabBtn = document.getElementById('prevTabBtn');
  const nextTabBtn = document.getElementById('nextTabBtn');
  const filterBtns = document.querySelectorAll('.toolbar-filter-btn[data-filter]');
  const shareBtn = document.getElementById('headerShareBtn');
  const readAloudBtn = document.getElementById('readAloudBtn');
  const speedSelect = document.getElementById('readSpeedSelect');
  const voiceSelect = document.getElementById('readVoiceSelect');
  const zoomInBtn = document.getElementById('zoomInBtn');
  const zoomOutBtn = document.getElementById('zoomOutBtn');
  const resetBtn = document.getElementById('resetExpBtn');
  const sidebarCollapseBtn = document.getElementById('sidebarCollapseBtn');
  const sidebarList = document.getElementById('sidebarNavList');
  const floatingSidebarTab = document.getElementById('floatingSidebarTab');
  const mainCard = document.querySelector('.exp-main-card');

  let currentTabIndex = 0;
  let zoomLevel = 100;
  let isSpeaking = false;
  let speechUtterance = null;
  let availableVoices = [];

  // ============================================================
  // 1. Tab Activation Function
  // ============================================================
  function activateTab(tabId, smoothScroll = false) {
    const targetIdx = TABS_ORDER.indexOf(tabId);
    if (targetIdx !== -1) {
      currentTabIndex = targetIdx;
    }

    // Update Sidebar Navigation Buttons
    tabButtons.forEach((btn) => {
      const isTarget = btn.dataset.tab === tabId;
      btn.classList.toggle('active', isTarget);
      btn.setAttribute('aria-selected', String(isTarget));
    });

    // Update Content Panels
    tabPanels.forEach((panel) => {
      const isTarget = panel.dataset.tabPanel === tabId;
      panel.hidden = !isTarget;
      panel.classList.toggle('active', isTarget);
    });

    // Update Toolbar Page Stepper: e.g. "1 / 7"
    if (pageCounter) {
      const displayIndex = targetIdx !== -1 ? targetIdx + 1 : 1;
      pageCounter.textContent = `${displayIndex} / ${TABS_ORDER.length}`;
    }

    // Update Prev / Next Buttons state
    if (prevTabBtn) {
      prevTabBtn.style.opacity = currentTabIndex === 0 ? '0.5' : '1';
      prevTabBtn.disabled = currentTabIndex === 0;
    }
    if (nextTabBtn) {
      nextTabBtn.style.opacity = currentTabIndex === TABS_ORDER.length - 1 ? '0.5' : '1';
      nextTabBtn.disabled = currentTabIndex === TABS_ORDER.length - 1;
    }

    // Update Filter Buttons state
    filterBtns.forEach((btn) => {
      const filter = btn.dataset.filter;
      if (filter === 'all') {
        btn.classList.toggle('active', tabId === 'aim');
      } else if (filter === 'theory') {
        btn.classList.toggle('active', tabId === 'theory');
      } else if (filter === 'interactive') {
        btn.classList.toggle('active', tabId === 'simulation');
      }
    });

    // Stop speaking if switching tabs
    if (window.speechSynthesis && window.speechSynthesis.speaking) {
      stopSpeech();
    }

    if (smoothScroll && mainCard) {
      mainCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  // Bind Sidebar Nav Buttons
  tabButtons.forEach((button) => {
    button.addEventListener('click', () => {
      activateTab(button.dataset.tab, false);
    });
  });

  // Prev / Next Page Controls
  if (prevTabBtn) {
    prevTabBtn.addEventListener('click', () => {
      if (currentTabIndex > 0) {
        activateTab(TABS_ORDER[currentTabIndex - 1], false);
      }
    });
  }

  if (nextTabBtn) {
    nextTabBtn.addEventListener('click', () => {
      if (currentTabIndex < TABS_ORDER.length - 1) {
        activateTab(TABS_ORDER[currentTabIndex + 1], false);
      }
    });
  }

  // Toolbar Filter Buttons
  filterBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const filter = btn.dataset.filter;
      if (filter === 'all') {
        activateTab('aim', false);
      } else if (filter === 'theory') {
        activateTab('theory', false);
      } else if (filter === 'interactive') {
        activateTab('simulation', false);
      }
    });
  });

  // ============================================================
  // 2. Read Aloud (Web Speech API Integration)
  // ============================================================
  function initSpeechVoices() {
    if (!('speechSynthesis' in window)) return;

    function populateVoices() {
      availableVoices = window.speechSynthesis.getVoices();
      if (!voiceSelect) return;
      
      voiceSelect.innerHTML = '<option value="auto">Voice: Auto</option>';
      availableVoices
        .filter((v) => v.lang.startsWith('en'))
        .slice(0, 5)
        .forEach((voice, i) => {
          const opt = document.createElement('option');
          opt.value = i;
          opt.textContent = `Voice: ${voice.name.split(' ')[0]}`;
          voiceSelect.appendChild(opt);
        });
    }

    populateVoices();
    if (speechSynthesis.onvoiceschanged !== undefined) {
      speechSynthesis.onvoiceschanged = populateVoices;
    }
  }

  function stopSpeech() {
    if ('speechSynthesis' in window) {
      window.speechSynthesis.cancel();
      isSpeaking = false;
      if (readAloudBtn) {
        readAloudBtn.classList.remove('speaking');
        readAloudBtn.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon>
            <path d="M15.54 8.46a5 5 0 0 1 0 7.07"></path>
            <path d="M19.07 4.93a10 10 0 0 1 0 14.14"></path>
          </svg>
          <span>Read Aloud</span>
        `;
      }
    }
  }

  function startSpeech() {
    if (!('speechSynthesis' in window)) {
      showToast('Text-to-speech is not supported in this browser.');
      return;
    }

    const activePanel = document.querySelector('.tab-content-panel.active') || document.querySelector('.tab-content-panel:not([hidden])');
    if (!activePanel) return;

    // Get plain text representation
    const textToRead = activePanel.innerText.replace(/\s+/g, ' ').trim();
    if (!textToRead) return;

    window.speechSynthesis.cancel();

    speechUtterance = new SpeechSynthesisUtterance(textToRead);
    
    // Set Speed
    if (speedSelect) {
      const speedVal = parseFloat(speedSelect.value) || 1.0;
      speechUtterance.rate = speedVal;
    }

    // Set Voice
    if (voiceSelect && voiceSelect.value !== 'auto' && availableVoices.length > 0) {
      const vIndex = parseInt(voiceSelect.value, 10);
      if (availableVoices[vIndex]) {
        speechUtterance.voice = availableVoices[vIndex];
      }
    }

    speechUtterance.onend = () => {
      stopSpeech();
    };

    speechUtterance.onerror = () => {
      stopSpeech();
    };

    window.speechSynthesis.speak(speechUtterance);
    isSpeaking = true;

    if (readAloudBtn) {
      readAloudBtn.classList.add('speaking');
      readAloudBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <rect x="6" y="4" width="4" height="16"></rect>
          <rect x="14" y="4" width="4" height="16"></rect>
        </svg>
        <span>Stop</span>
      `;
    }
  }

  if (readAloudBtn) {
    readAloudBtn.addEventListener('click', () => {
      if (isSpeaking) {
        stopSpeech();
      } else {
        startSpeech();
      }
    });
  }

  if (speedSelect) {
    speedSelect.addEventListener('change', () => {
      if (isSpeaking) {
        startSpeech();
      }
    });
  }

  // ============================================================
  // 3. Zoom Controls (- / +)
  // ============================================================
  if (zoomInBtn && mainCard) {
    zoomInBtn.addEventListener('click', () => {
      if (zoomLevel < 130) {
        zoomLevel += 5;
        mainCard.style.fontSize = `${zoomLevel}%`;
      }
    });
  }

  if (zoomOutBtn && mainCard) {
    zoomOutBtn.addEventListener('click', () => {
      if (zoomLevel > 85) {
        zoomLevel -= 5;
        mainCard.style.fontSize = `${zoomLevel}%`;
      }
    });
  }

  // Reset Button (↻)
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      stopSpeech();
      zoomLevel = 100;
      if (mainCard) mainCard.style.fontSize = '100%';
      // If simulation tab has reset handler, trigger it
      if (typeof window.resetSimulation === 'function') {
        window.resetSimulation();
      }
      showToast('Experiment state refreshed.');
    });
  }

  // ============================================================
  // 4. Share Button & Toast Notification
  // ============================================================
  function showToast(message) {
    let toast = document.getElementById('expToastNotification');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'expToastNotification';
      toast.className = 'exp-toast';
      document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => {
      toast.classList.remove('show');
    }, 2800);
  }

  if (shareBtn) {
    shareBtn.addEventListener('click', () => {
      if (navigator.clipboard && window.location.href) {
        navigator.clipboard.writeText(window.location.href).then(() => {
          showToast('Experiment link copied to clipboard!');
        }).catch(() => {
          showToast('Failed to copy link.');
        });
      } else {
        showToast('Link sharing ready.');
      }
    });
  }

  // ============================================================
  // 5. Sidebar Accordion & Mobile Drawer
  // ============================================================
  if (sidebarCollapseBtn && sidebarList) {
    sidebarCollapseBtn.addEventListener('click', () => {
      const isHidden = sidebarList.style.display === 'none';
      sidebarList.style.display = isHidden ? 'flex' : 'none';
      sidebarCollapseBtn.innerHTML = isHidden
        ? '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><polyline points="18 15 12 9 6 15"></polyline></svg>'
        : '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>';
    });
  }

  if (floatingSidebarTab) {
    floatingSidebarTab.addEventListener('click', () => {
      const sidebarCard = document.querySelector('.exp-sidebar-card');
      if (sidebarCard) {
        sidebarCard.scrollIntoView({ behavior: 'smooth' });
      }
    });
  }

  // Initialize Voices on Load
  initSpeechVoices();

  // Initial State: Activate first tab
  activateTab('aim', false);

  // Expose toast helper globally
  window.showToast = showToast;
})();
