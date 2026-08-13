// mobile nav menu
var burger = document.getElementById('burger');
var navLinks = document.getElementById('navLinks');

if (burger && navLinks) {
  burger.addEventListener('click', function () {
    navLinks.classList.toggle('open');
    var isOpen = navLinks.classList.contains('open');
    burger.setAttribute('aria-expanded', isOpen);
  });
}

// fade in sections when they scroll into view
var revealEls = document.querySelectorAll('.reveal');

if ('IntersectionObserver' in window && revealEls.length > 0) {
  var observer = new IntersectionObserver(function (entries) {
    for (var i = 0; i < entries.length; i++) {
      var entry = entries[i];
      if (entry.isIntersecting) {
        entry.target.classList.add('in');
        observer.unobserve(entry.target);
      }
    }
  }, { threshold: 0.15 });

  for (var j = 0; j < revealEls.length; j++) {
    observer.observe(revealEls[j]);
  }
} else {
  // no IntersectionObserver support, just show everything
  for (var k = 0; k < revealEls.length; k++) {
    revealEls[k].classList.add('in');
  }
}

// footer year
var yearEl = document.getElementById('year');
if (yearEl) {
  yearEl.textContent = new Date().getFullYear();
}
