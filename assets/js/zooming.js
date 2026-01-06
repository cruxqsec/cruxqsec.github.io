import Zooming from '../lib/js/zooming-v2.1.1.min.js';

document.addEventListener('DOMContentLoaded', function () {

    let bgColor;
    if (localStorage.appearance === 'dark' || (!('appearance' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
        bgColor = '#333';
    } else {
        bgColor = '#fff';
    }

    zooming = new Zooming({
        transitionDuration: 0.2,
        bgColor: bgColor,
    });
    zooming.listen('.prose img');


  function applyZoomBgFromAppearance() {
    zooming.config({
      bgColor: document.documentElement.classList.contains('dark')
        ? '#333'
        : '#fff',
    });
  }

  applyZoomBgFromAppearance();

  new MutationObserver(applyZoomBgFromAppearance)
    .observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class'],
    });

});
