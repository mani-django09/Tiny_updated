/**
 * TinyURL.run - Optimized JavaScript
 * Performance-focused JS with mobile optimizations
 */

// Use strict mode for better error catching and performance
'use strict';

// Main initialization - using DOMContentLoaded for faster perceived loading
document.addEventListener('DOMContentLoaded', function() {
  // Initialize critical components immediately
  setupFormValidation();
  
  // Defer non-critical initializations
  if ('requestIdleCallback' in window) {
    // Use requestIdleCallback if available (modern browsers)
    requestIdleCallback(() => {
      initDeferredFunctions();
    });
  } else {
    // Fallback for browsers without requestIdleCallback
    setTimeout(() => {
      initDeferredFunctions();
    }, 200);
  }
});

/**
 * Initialize non-critical functions after page is interactive
 */
function initDeferredFunctions() {
  // Initialize Bootstrap tooltips if needed
  initTooltips();
  
  // Copy button functionality
  setupCopyButtons();
  
  // Toggle advanced options
  setupAdvancedOptions();
  
  // Smooth scroll with throttling
  setupSmoothScroll();
  
  // Counter animation with intersection observer
  setupCounterAnimation();
  
  // Add schema markup for SEO
  addSchemaMarkup();
  
  // Initialize lazy loading for images
  setupLazyLoading();
  
  // Initialize particles for hero section if exists
  if (document.getElementById('particles-js')) {
    if (typeof particlesJS !== 'undefined') {
      initParticles();
    } else {
      // Load particles.js dynamically if not loaded
      loadScript('https://cdn.jsdelivr.net/npm/particles.js@2.0.0/particles.min.js', initParticles);
    }
  }
}

/**
 * Dynamic script loader with callback
 */
function loadScript(src, callback) {
  const script = document.createElement('script');
  script.src = src;
  script.async = true;
  script.onload = callback;
  document.head.appendChild(script);
}

/**
 * Initialize Bootstrap tooltips with performance optimizations
 */
function initTooltips() {
  // Only initialize if Bootstrap is loaded
  if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
      return new bootstrap.Tooltip(tooltipTriggerEl, {
        boundary: 'window', // Improves performance on mobile
        customClass: 'tooltip-sm' // Smaller tooltips on mobile
      });
    });
  }
}

/**
 * Initialize particles.js with optimized settings for mobile
 */
function initParticles() {
  if (typeof particlesJS !== 'undefined') {
    // Detect if mobile device to use reduced settings
    const isMobile = window.innerWidth < 768;
    
    particlesJS("particles-js", {
      "particles": {
        "number": {
          "value": isMobile ? 30 : 60, // Fewer particles on mobile
          "density": {
            "enable": true,
            "value_area": 800
          }
        },
        "color": {
          "value": "#ffffff"
        },
        "shape": {
          "type": "circle",
          "stroke": {
            "width": 0,
            "color": "#000000"
          }
        },
        "opacity": {
          "value": 0.3,
          "random": true,
          "anim": {
            "enable": true,
            "speed": isMobile ? 0.4 : 0.8, // Slower animation on mobile
            "opacity_min": 0.1,
            "sync": false
          }
        },
        "size": {
          "value": isMobile ? 2 : 3, // Smaller particles on mobile
          "random": true,
          "anim": {
            "enable": true,
            "speed": isMobile ? 1 : 2, // Slower on mobile
            "size_min": 0.1,
            "sync": false
          }
        },
        "line_linked": {
          "enable": true,
          "distance": isMobile ? 100 : 150, // Shorter distance on mobile
          "color": "#ffffff",
          "opacity": 0.2,
          "width": 1
        },
        "move": {
          "enable": true,
          "speed": isMobile ? 0.4 : 0.8, // Slower for mobile
          "direction": "none",
          "random": true,
          "straight": false,
          "out_mode": "out",
          "bounce": false,
          "attract": {
            "enable": false,
            "rotateX": 600,
            "rotateY": 1200
          }
        }
      },
      "interactivity": {
        "detect_on": "canvas",
        "events": {
          "onhover": {
            "enable": !isMobile, // Disable hover effects on mobile
            "mode": "bubble"
          },
          "onclick": {
            "enable": true,
            "mode": "push"
          },
          "resize": true
        },
        "modes": {
          "grab": {
            "distance": 140,
            "line_linked": {
              "opacity": 1
            }
          },
          "bubble": {
            "distance": 200,
            "size": 6,
            "duration": 2,
            "opacity": 0.8,
            "speed": 3
          },
          "repulse": {
            "distance": 200,
            "duration": 0.4
          },
          "push": {
            "particles_nb": isMobile ? 2 : 4 // Fewer particles added on mobile
          },
          "remove": {
            "particles_nb": 2
          }
        }
      },
      "retina_detect": !isMobile // Disable retina detection on mobile
    });
  }
}

/**
 * Copy to clipboard with better error handling
 */
function copyToClipboard(text, buttonElement) {
  // Use Clipboard API when available
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text)
      .then(() => showCopySuccess(buttonElement))
.catch(() => fallbackCopy(text, buttonElement));
  } else {
    // Fallback for browsers without Clipboard API
    fallbackCopy(text, buttonElement);
  }
}

/**
 * Fallback copy method for older browsers
 */
function fallbackCopy(text, buttonElement) {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  
  try {
    const successful = document.execCommand('copy');
    if (successful) {
      showCopySuccess(buttonElement);
    } else {
      alert('Failed to copy. Please select and copy manually.');
    }
  } catch (err) {
    console.error('Failed to copy: ', err);
    alert('Failed to copy. Please select and copy manually.');
  }
  
  document.body.removeChild(textarea);
}

/**
 * Show copy success animation
 */
function showCopySuccess(buttonElement) {
  if (!buttonElement) return;
  
  // Store original content
  const originalHTML = buttonElement.innerHTML;
  const originalClass = buttonElement.className;
  
  // Update button to show success
  buttonElement.innerHTML = '<i class="bi bi-check-circle me-1"></i>Copied!';
  buttonElement.classList.remove('btn-outline-secondary');
  buttonElement.classList.add('btn-success');
  
  // Reset after animation
  setTimeout(() => {
    buttonElement.innerHTML = originalHTML;
    buttonElement.className = originalClass;
  }, 2000);
}

/**
 * Setup all copy buttons with efficient event handling
 */
function setupCopyButtons() {
  const copyButtons = document.querySelectorAll('.copy-btn');
  
  copyButtons.forEach(button => {
    button.addEventListener('click', function() {
      const url = this.getAttribute('data-url');
      if (!url) return;
      
      copyToClipboard(url, this);
    });
  });
}

/**
 * Form validation with improved user feedback
 */
function setupFormValidation() {
  const urlForm = document.getElementById('shortener-form');
  
  if (!urlForm) return;
  
  urlForm.addEventListener('submit', function(event) {
    const urlInput = document.getElementById('id_original_url');
    const customShortCodeInput = document.getElementById('id_custom_alias');
    
    if (!urlInput) return;
    
    let isValid = true;
    
    // Validate URL format
    if (urlInput.value && !isValidURL(urlInput.value)) {
      event.preventDefault();
      showError(urlInput, 'Please enter a valid URL, including http:// or https://');
      isValid = false;
    } else {
      // Clear error if valid
      clearError(urlInput);
    }
    
    // Validate custom short code if provided
    if (customShortCodeInput && customShortCodeInput.value) {
      if (!isValidShortCode(customShortCodeInput.value)) {
        event.preventDefault();
        showError(customShortCodeInput, 'Custom short code can only contain letters, numbers, hyphens, and underscores');
        isValid = false;
      } else {
        // Clear error if valid
        clearError(customShortCodeInput);
      }
    }
    
    // Add form-level success feedback for better UX
    if (isValid) {
      addSubmitAnimation(urlForm);
    }
  });
  
  // Add real-time validation feedback for better UX
  const urlInput = document.getElementById('id_original_url');
  if (urlInput) {
    // Throttled validation to avoid performance issues
    let validationTimeout;
    urlInput.addEventListener('input', function() {
      clearTimeout(validationTimeout);
      validationTimeout = setTimeout(() => {
        if (this.value && !isValidURL(this.value)) {
          showError(this, 'Please enter a valid URL, including http:// or https://');
        } else if (this.value) {
          clearError(this);
          showSuccess(this);
        } else {
          clearError(this);
        }
      }, 300);
    });
  }
  
  // Real-time validation for custom alias
  const customAliasInput = document.getElementById('id_custom_alias');
  if (customAliasInput) {
    let aliasTimeout;
    customAliasInput.addEventListener('input', function() {
      clearTimeout(aliasTimeout);
      aliasTimeout = setTimeout(() => {
        if (this.value && !isValidShortCode(this.value)) {
          showError(this, 'Custom short code can only contain letters, numbers, hyphens, and underscores');
        } else if (this.value) {
          clearError(this);
          showSuccess(this);
        } else {
          clearError(this);
        }
      }, 300);
    });
  }
}

/**
 * Add submit animation to form
 */
function addSubmitAnimation(form) {
  const submitButton = form.querySelector('button[type="submit"]');
  if (!submitButton) return;
  
  const originalText = submitButton.innerHTML;
  submitButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Processing...';
  submitButton.disabled = true;
  
  // Reset after 5 seconds in case of network issues
  setTimeout(() => {
    submitButton.innerHTML = originalText;
    submitButton.disabled = false;
  }, 5000);
}

/**
 * Validate URL format
 */
function isValidURL(url) {
  try {
    new URL(url);
    return true;
  } catch (err) {
    return false;
  }
}

/**
 * Validate short code format
 */
function isValidShortCode(code) {
  const pattern = /^[a-zA-Z0-9_-]+$/;
  return pattern.test(code);
}

/**
 * Show error message for form fields
 */
function showError(inputElement, message) {
  // Clear previous error
  clearError(inputElement);
  
  // Add error class
  inputElement.classList.add('is-invalid');
  
  // Create error message
  const errorDiv = document.createElement('div');
  errorDiv.className = 'invalid-feedback';
  errorDiv.textContent = message;
  
  // Add after input
  inputElement.parentElement.appendChild(errorDiv);
}

/**
 * Clear error message
 */
function clearError(inputElement) {
  // Remove error class
  inputElement.classList.remove('is-invalid');
  
  // Remove error message
  const existingError = inputElement.parentElement.querySelector('.invalid-feedback');
  if (existingError) {
    existingError.remove();
  }
  
  // Remove success class if switching back to neutral state
  inputElement.classList.remove('is-valid');
}

/**
 * Show success indicator
 */
function showSuccess(inputElement) {
  inputElement.classList.add('is-valid');
}

/**
 * Setup advanced options toggle and dependencies
 */
function setupAdvancedOptions() {
  const showAdvancedOptionsCheckbox = document.getElementById('showAdvancedOptions');
  const advancedOptionsDiv = document.getElementById('advancedOptions');
  
  if (showAdvancedOptionsCheckbox && advancedOptionsDiv) {
    showAdvancedOptionsCheckbox.addEventListener('change', function() {
      if (this.checked) {
        advancedOptionsDiv.classList.remove('d-none');
      } else {
        advancedOptionsDiv.classList.add('d-none');
      }
    });
  }
  
  // Expiry options
  const expiryOptions = document.getElementById('id_expiry_options');
  const customExpiryField = document.getElementById('customExpiryField');
  
  if (expiryOptions && customExpiryField) {
    expiryOptions.addEventListener('change', function() {
      if (this.value === 'custom') {
        customExpiryField.classList.remove('d-none');
      } else {
        customExpiryField.classList.add('d-none');
      }
    });
  }
  
  // Password protection toggle
  const passwordProtectCheckbox = document.getElementById('id_password_protect');
  const passwordField = document.getElementById('passwordField');
  
  if (passwordProtectCheckbox && passwordField) {
    passwordProtectCheckbox.addEventListener('change', function() {
      if (this.checked) {
        passwordField.classList.remove('d-none');
      } else {
        passwordField.classList.add('d-none');
      }
    });
  }
}

/**
 * Setup smooth scrolling with throttling for better performance
 */
function setupSmoothScroll() {
  // Throttle function to limit execution frequency
  const throttle = (func, limit) => {
    let inThrottle;
    return function() {
      const args = arguments;
      const context = this;
      if (!inThrottle) {
        func.apply(context, args);
        inThrottle = true;
        setTimeout(() => inThrottle = false, limit);
      }
    };
  };
  
  // Get all anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      // Skip if just '#'
      if (this.getAttribute('href') === '#') return;
      
      e.preventDefault();
      
      const targetId = this.getAttribute('href');
      const targetElement = document.querySelector(targetId);
      
      if (targetElement) {
        // Get header height for offset
        const headerHeight = document.querySelector('.navbar')?.offsetHeight || 0;
        const offsetTop = targetElement.offsetTop - headerHeight - 20;
        
        window.scrollTo({
          top: offsetTop,
          behavior: 'smooth'
        });
      }
    });
  });
  
  // Scroll to top buttons with throttling
  document.querySelectorAll('a[href="#top"]').forEach(anchor => {
    anchor.addEventListener('click', throttle(function(e) {
      e.preventDefault();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }, 100));
  });
  
  // Add scroll indicator
  const scrollProgress = document.createElement('div');
  scrollProgress.className = 'scroll-progress';
  document.body.appendChild(scrollProgress);
  
  // Update scroll progress indicator with throttling
  window.addEventListener('scroll', throttle(function() {
    const totalHeight = document.body.scrollHeight - window.innerHeight;
    const progress = (window.pageYOffset / totalHeight) * 100;
    scrollProgress.style.width = progress + '%';
  }, 10));
}

/**
 * Setup counter animation with IntersectionObserver
 */
function setupCounterAnimation() {
  const counters = document.querySelectorAll('.counter');
  
  if (counters.length === 0 || !('IntersectionObserver' in window)) return;
  
  const animateCounter = (counter, target) => {
    // Determine if counter has suffix
    const hasPlus = counter.textContent.includes('+');
    const hasK = counter.textContent.includes('K');
    const hasM = counter.textContent.includes('M');
    
    // Calculate multiplier based on suffix
    let multiplier = 1;
    if (hasK) multiplier = 1000;
    if (hasM) multiplier = 1000000;
    
    // Calculate target number
    const targetNum = parseInt(target.replace(/[^\d]/g, '')) * multiplier;
    
    // Set duration based on number size for smoother animation
    const duration = Math.min(2000, Math.max(1000, targetNum / 10));
    
    // Calculate increment per frame for smooth animation
    const increment = targetNum / (duration / 16);
    
    let current = 0;
    const timer = setInterval(() => {
      current += increment;
      
      // Format with appropriate suffix
      if (current >= targetNum) {
        // Final value with proper formatting
        counter.textContent = formatCounterValue(targetNum, hasK, hasM, hasPlus);
        clearInterval(timer);
      } else {
        // Intermediate value with proper formatting
        counter.textContent = formatCounterValue(Math.floor(current), hasK, hasM, hasPlus);
      }
    }, 16);
  };
  
  // Format counter value with appropriate suffix
  const formatCounterValue = (value, hasK, hasM, hasPlus) => {
    if (hasM) {
      return (value / 1000000).toFixed(value < 10000000 ? 1 : 0) + 'M' + (hasPlus ? '+' : '');
    } else if (hasK) {
      return (value / 1000).toFixed(value < 10000 ? 1 : 0) + 'K' + (hasPlus ? '+' : '');
    } else {
      return value.toLocaleString() + (hasPlus ? '+' : '');
    }
  };
  
  // Use Intersection Observer for better performance
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const counter = entry.target;
        const target = counter.textContent;
        
        // Start animation
        animateCounter(counter, target);
        
        // Unobserve after animation starts
        observer.unobserve(counter);
      }
    });
  }, { threshold: 0.1 });
  
  // Observe each counter
  counters.forEach(counter => {
    observer.observe(counter);
  });
}

/**
 * Add schema markup for better SEO
 */
function addSchemaMarkup() {
  // Only add if not already present
  if (document.querySelector('script[type="application/ld+json"]')) return;
  
  const schemaScript = document.createElement('script');
  schemaScript.type = 'application/ld+json';
  schemaScript.innerHTML = `
  {
    "@context": "https://schema.org",
    "@type": "WebApplication",
    "name": "TinyURL.run",
    "url": "https://tinyurl.run/",
    "description": "TinyURL.run is a free URL shortener service that transforms long URLs into short, memorable links with tracking capabilities.",
    "applicationCategory": "WebApplication",
    "operatingSystem": "All",
    "offers": {
      "@type": "Offer",
      "price": "0",
      "priceCurrency": "USD"
    },
    "featureList": "URL Shortening, Custom Aliases, Analytics, QR Code Generation, Password Protection",
    "screenshot": "https://tinyurl.run/static/img/screenshot.jpg",
    "aggregateRating": {
      "@type": "AggregateRating",
      "ratingValue": "4.8",
      "ratingCount": "1024"
    }
  }
  `;
  document.head.appendChild(schemaScript);
}

/**
 * Setup lazy loading for images
 */
function setupLazyLoading() {
  const lazyImages = document.querySelectorAll('img[data-src]');
  
  if (lazyImages.length === 0) return;
  
  // Use Intersection Observer API if available
  if ('IntersectionObserver' in window) {
    const imageObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const img = entry.target;
          img.src = img.dataset.src;
          img.classList.add('loaded');
          imageObserver.unobserve(img);
        }
      });
    });
    
    lazyImages.forEach(img => {
      imageObserver.observe(img);
    });
  } else {
    // Fallback for browsers without IntersectionObserver
    // Simple scroll-based lazy loading
    const lazyLoad = () => {
      lazyImages.forEach(img => {
        if (img.getBoundingClientRect().top <= window.innerHeight && 
            img.getBoundingClientRect().bottom >= 0 && 
            getComputedStyle(img).display !== 'none') {
          img.src = img.dataset.src;
          img.classList.add('loaded');
        }
      });
    };
    
    // Initial check
    lazyLoad();
    
    // Add throttled scroll listener
    let lazyLoadThrottleTimeout;
    window.addEventListener('scroll', function() {
      if (lazyLoadThrottleTimeout) {
        clearTimeout(lazyLoadThrottleTimeout);
      }
      
      lazyLoadThrottleTimeout = setTimeout(lazyLoad, 200);
    });
  }
}

/**
 * Generate QR code via AJAX
 */
function generateQR(url) {
  if (!url) return;
  
  const qrContainer = document.getElementById('qrCodeContainer');
  if (!qrContainer) return;
  
  // Show loading indicator
  qrContainer.innerHTML = '<div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div>';
  
  // Use a third-party API to avoid server load
  const qrImageUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(url)}`;
  
  // Create image element
  const img = new Image();
  img.src = qrImageUrl;
  img.alt = "QR Code";
  img.className = "img-fluid";
  
  // Replace loading indicator when image loads
  img.onload = function() {
    qrContainer.innerHTML = '';
    qrContainer.appendChild(img);
  };
  
  // Handle errors
  img.onerror = function() {
    qrContainer.innerHTML = '<div class="alert alert-danger">Failed to generate QR code. Please try again.</div>';
  };
}

// Initialize when DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
  // Set up responsive navbar behavior
  setupResponsiveNavbar();
  
  // Initialize AOS animations if present
  if (typeof AOS !== 'undefined') {
    AOS.init({
      duration: 800,
      once: true,
      disable: 'mobile' // Disable on mobile for performance
    });
  }
});

/**
 * Set up responsive navbar
 */
function setupResponsiveNavbar() {
  const navbar = document.querySelector('.navbar');
  if (!navbar) return;
  
  // Add scrolled class on scroll
  window.addEventListener('scroll', function() {
    if (window.scrollY > 50) {
      navbar.classList.add('navbar-scrolled');
    } else {
      navbar.classList.remove('navbar-scrolled');
    }
  });
  
  // Add active class to current nav item
  const currentLocation = window.location.pathname;
  const navLinks = document.querySelectorAll('.nav-link');
  
  navLinks.forEach(link => {
    try {
      const linkPath = new URL(link.href, window.location.origin).pathname;
      if (linkPath === currentLocation || 
          (currentLocation !== '/' && linkPath !== '/' && currentLocation.includes(linkPath))) {
        link.classList.add('active');
      }
    } catch (e) {
      console.error('Error processing nav link:', e);
    }
  });
  
  // Handle mobile menu toggle for performance
  const navbarToggler = document.querySelector('.navbar-toggler');
  const navbarCollapse = document.querySelector('.navbar-collapse');
  
  if (navbarToggler && navbarCollapse) {
    navbarToggler.addEventListener('click', function() {
      // Toggle with class rather than Bootstrap JS for better performance
      navbarCollapse.classList.toggle('show');
    });
    
    // Close menu when clicking outside
    document.addEventListener('click', function(event) {
      if (!navbarToggler.contains(event.target) && 
          !navbarCollapse.contains(event.target) && 
          navbarCollapse.classList.contains('show')) {
        navbarCollapse.classList.remove('show');
      }
    });
  }
}

/**
 * Enhanced form validation with improved custom short code validation
 */
function setupFormValidation() {
    const urlForm = document.getElementById('shortener-form');
    
    if (!urlForm) return;
    
    // Get form elements
    const urlInput = document.getElementById('id_original_url');
    const customShortCodeInput = document.getElementById('id_custom_short_code');
    
    // Form submission validation
    urlForm.addEventListener('submit', function(event) {
        let isValid = true;
        
        // Validate URL
        if (urlInput && urlInput.value) {
            if (!isValidURL(urlInput.value)) {
                event.preventDefault();
                showError(urlInput, 'Please enter a valid URL, including http:// or https://');
                isValid = false;
            } else {
                clearError(urlInput);
            }
        }
        
        // Validate custom short code
        if (customShortCodeInput && customShortCodeInput.value.trim()) {
            const validationResult = validateCustomShortCode(customShortCodeInput.value.trim());
            if (!validationResult.isValid) {
                event.preventDefault();
                showError(customShortCodeInput, validationResult.message);
                isValid = false;
            } else {
                clearError(customShortCodeInput);
            }
        }
        
        // Add form-level success feedback for better UX
        if (isValid) {
            addSubmitAnimation(urlForm);
        }
    });
    
    // Real-time validation for URL input
    if (urlInput) {
        let urlValidationTimeout;
        urlInput.addEventListener('input', function() {
            clearTimeout(urlValidationTimeout);
            urlValidationTimeout = setTimeout(() => {
                const value = this.value.trim();
                if (value) {
                    if (!isValidURL(value)) {
                        showError(this, 'Please enter a valid URL, including http:// or https://');
                    } else {
                        clearError(this);
                        showSuccess(this);
                    }
                } else {
                    clearError(this);
                }
            }, 300);
        });
    }
    
    // Enhanced real-time validation for custom short code
    if (customShortCodeInput) {
        let aliasTimeout;
        let duplicateCheckTimeout;
        
        customShortCodeInput.addEventListener('input', function() {
            clearTimeout(aliasTimeout);
            clearTimeout(duplicateCheckTimeout);
            
            const value = this.value.trim();
            
            // Clear any existing error states first
            clearError(this);
            
            if (!value) {
                // Empty input is okay (optional field)
                return;
            }
            
            // Immediate validation (no delay for instant feedback)
            const validationResult = validateCustomShortCode(value);
            if (!validationResult.isValid) {
                showError(this, validationResult.message);
                return;
            }
            
            // Show success for valid format
            showSuccess(this);
            
            // Check for duplicates after a delay (to avoid too many requests)
            duplicateCheckTimeout = setTimeout(() => {
                checkShortCodeAvailability(value, this);
            }, 500);
        });
        
        // Also validate on blur for better UX
        customShortCodeInput.addEventListener('blur', function() {
            const value = this.value.trim();
            if (value) {
                const validationResult = validateCustomShortCode(value);
                if (!validationResult.isValid) {
                    showError(this, validationResult.message);
                } else {
                    checkShortCodeAvailability(value, this);
                }
            }
        });
    }
}

/**
 * Enhanced custom short code validation function
 */
function validateCustomShortCode(code) {
    // Check length constraints
    if (code.length < 3) {
        return {
            isValid: false,
            message: 'Custom short code must be at least 3 characters long.'
        };
    }
    
    if (code.length > 10) {
        return {
            isValid: false,
            message: 'Custom short code cannot be more than 10 characters long.'
        };
    }
    
    // Check for valid characters
    const validPattern = /^[a-zA-Z0-9_-]+$/;
    if (!validPattern.test(code)) {
        return {
            isValid: false,
            message: 'Custom short code can only contain letters, numbers, hyphens, and underscores.'
        };
    }
    
    // Check against reserved words
    const reservedWords = [
        'admin', 'api', 'www', 'mail', 'ftp', 'localhost', 'stats', 'analytics',
        'dashboard', 'login', 'logout', 'register', 'signup', 'signin', 'user',
        'users', 'profile', 'settings', 'config', 'help', 'support', 'contact',
        'about', 'terms', 'privacy', 'policy', 'legal', 'dmca', 'abuse',
        'security', 'qr', 'qrcode', 'short', 'url', 'link', 'redirect',
        'goto', 'go', 'click', 'visit', 'view', 'show', 'display', 'index',
        'home', 'test', 'demo', 'example', 'sample'
    ];
    
    if (reservedWords.includes(code.toLowerCase())) {
        return {
            isValid: false,
            message: `The short code '${code}' is reserved. Please choose a different one.`
        };
    }
    
    return { isValid: true };
}

/**
 * Check if short code is available (AJAX call to backend)
 */
function checkShortCodeAvailability(code, inputElement) {
    // Create a simple availability check endpoint call
    fetch('/check-availability/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken()
        },
        body: JSON.stringify({ short_code: code })
    })
    .then(response => response.json())
    .then(data => {
        if (data.available) {
            showSuccess(inputElement);
            showAvailabilityMessage(inputElement, `✓ "${code}" is available!`, 'success');
        } else {
            showError(inputElement, `The short code '${code}' is not available. Please choose a different one.`);
        }
    })
    .catch(error => {
        console.log('Availability check failed:', error);
        // Don't show error to user for availability check failures
        // Just remove any existing availability messages
        removeAvailabilityMessage(inputElement);
    });
}

/**
 * Show availability message below input
 */
function showAvailabilityMessage(inputElement, message, type) {
    removeAvailabilityMessage(inputElement);
    
    const messageDiv = document.createElement('div');
    messageDiv.className = `availability-message small mt-1 text-${type === 'success' ? 'success' : 'danger'}`;
    messageDiv.textContent = message;
    messageDiv.style.fontSize = '0.875rem';
    
    inputElement.parentElement.appendChild(messageDiv);
    
    // Auto-remove success messages after 3 seconds
    if (type === 'success') {
        setTimeout(() => removeAvailabilityMessage(inputElement), 3000);
    }
}

/**
 * Remove availability message
 */
function removeAvailabilityMessage(inputElement) {
    const existingMessage = inputElement.parentElement.querySelector('.availability-message');
    if (existingMessage) {
        existingMessage.remove();
    }
}

/**
 * Get CSRF token for AJAX requests
 */
function getCSRFToken() {
    const name = 'csrftoken';
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

/**
 * Enhanced error display with better styling
 */
function showError(inputElement, message) {
    // Clear previous states
    clearError(inputElement);
    removeAvailabilityMessage(inputElement);
    
    // Add error class with animation
    inputElement.classList.add('is-invalid');
    inputElement.style.borderColor = '#dc3545';
    
    // Create error message with better styling
    const errorDiv = document.createElement('div');
    errorDiv.className = 'invalid-feedback d-block';
    errorDiv.innerHTML = `<i class="bi bi-exclamation-circle me-1"></i>${message}`;
    errorDiv.style.fontSize = '0.875rem';
    errorDiv.style.marginTop = '0.25rem';
    
    // Add after input with animation
    inputElement.parentElement.appendChild(errorDiv);
    
    // Add shake animation
    inputElement.style.animation = 'shake 0.5s';
    setTimeout(() => {
        inputElement.style.animation = '';
    }, 500);
}

/**
 * Enhanced success display
 */
function showSuccess(inputElement) {
    inputElement.classList.remove('is-invalid');
    inputElement.classList.add('is-valid');
    inputElement.style.borderColor = '#198754';
}

/**
 * Enhanced error clearing
 */
function clearError(inputElement) {
    // Remove error classes and styles
    inputElement.classList.remove('is-invalid', 'is-valid');
    inputElement.style.borderColor = '';
    inputElement.style.animation = '';
    
    // Remove error message
    const existingError = inputElement.parentElement.querySelector('.invalid-feedback');
    if (existingError) {
        existingError.remove();
    }
    
    // Remove availability message when clearing errors
    removeAvailabilityMessage(inputElement);
}

/**
 * Enhanced URL validation
 */
function isValidURL(url) {
    try {
        // Add protocol if missing
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }
        
        const urlObj = new URL(url);
        
        // Basic validation - must have a valid domain
        return urlObj.hostname && urlObj.hostname.includes('.');
    } catch (err) {
        return false;
    }
}

/**
 * Add CSS animations for better UX
 */
function addValidationStyles() {
    if (document.getElementById('validation-styles')) return;
    
    const style = document.createElement('style');
    style.id = 'validation-styles';
    style.textContent = `
        @keyframes shake {
            0%, 20%, 40%, 60%, 80% { transform: translateX(0); }
            10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
        }
        
        .form-control.is-valid {
            border-color: #198754;
            box-shadow: 0 0 0 0.2rem rgba(25, 135, 84, 0.25);
        }
        
        .form-control.is-invalid {
            border-color: #dc3545;
            box-shadow: 0 0 0 0.2rem rgba(220, 53, 69, 0.25);
        }
        
        .availability-message {
            animation: fadeIn 0.3s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-5px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .invalid-feedback {
            animation: slideDown 0.3s ease-out;
        }
        
        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
    `;
    document.head.appendChild(style);
}

// Initialize everything when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    addValidationStyles();
    setupFormValidation();
});