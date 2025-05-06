// // Debounce function (improves performance)
// function debounce(func, wait, immediate) {
//     var timeout;
//     return function() {
//       var context = this, args = arguments;
//       var later = function() {
//         timeout = null;
//         if (!immediate) func.apply(context, args);
//       };
//       var callNow = immediate && !timeout;
//       clearTimeout(timeout);
//       timeout = setTimeout(later, wait);
//       if (callNow) func.apply(context, args);
//     };
//   };
  
//   // Function to update the VERTICAL progress bar HEIGHT
//   function updateVerticalProgressBar() {
//     const container = document.getElementById('vertical-progress-container');
//     // Only run if the container element exists
//     if (!container) {
//       return;
//     }
  
//     const fillElement = container.querySelector('.vertical-progress-fill');
//     // Only run if the fill element exists
//     if (!fillElement) {
//       return;
//     }
  
//     const scrollY = window.scrollY || document.documentElement.scrollTop;
//     const viewportHeight = document.documentElement.clientHeight;
//     const totalPageHeight = document.documentElement.scrollHeight;
//     const scrollableDistance = totalPageHeight - viewportHeight;
  
//     let progressPercentage = 0;
//     // Calculate percentage only if the page is scrollable
//     if (scrollableDistance > 0) {
//       progressPercentage = (scrollY / scrollableDistance) * 100;
//     } else {
//       // If not scrollable, determine if we should show 0% or 100%
//       // If already scrolled (e.g. page loaded scrolled down) and height allows scroll, show 100%
//        if (scrollY > 0 && totalPageHeight > viewportHeight) {
//            progressPercentage = 100;
//        } else {
//            progressPercentage = 0; // Otherwise show 0%
//        }
//     }
  
//     // Ensure percentage is between 0 and 100
//     progressPercentage = Math.min(100, Math.max(0, progressPercentage));
  
//     // *** Update the HEIGHT of the fill element ***
//     fillElement.style.height = progressPercentage + '%';
//   }
  
//   // Add debounced event listeners for scroll and resize
//   window.addEventListener('scroll', debounce(updateVerticalProgressBar, 15), false);
//   window.addEventListener('resize', debounce(updateVerticalProgressBar, 50), false);
//   // Run once on load to set initial state
//   window.addEventListener('load', updateVerticalProgressBar);



// Debounce function (improves performance)
function debounce(func, wait, immediate) {
    var timeout;
    return function() {
      var context = this, args = arguments;
      var later = function() {
        timeout = null;
        if (!immediate) func.apply(context, args);
      };
      var callNow = immediate && !timeout;
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
      if (callNow) func.apply(context, args);
    };
  };
  
  // Function to update the HORIZONTAL progress bar WIDTH
  function updateHorizontalProgress() {
    const container = document.getElementById('horizontal-progress-bar');
    // Only run if the container element exists
    if (!container) {
      return;
    }
  
    const fillElement = container.querySelector('.bars');
    // Only run if the fill element exists
    if (!fillElement) {
      return;
    }
  
    const scrollY = window.scrollY || document.documentElement.scrollTop;
    const viewportHeight = document.documentElement.clientHeight;
    const totalPageHeight = document.documentElement.scrollHeight;
    const scrollableDistance = totalPageHeight - viewportHeight;
  
    let progressPercentage = 0;
    // Calculate percentage only if the page is scrollable
    if (scrollableDistance > 0) {
      progressPercentage = (scrollY / scrollableDistance) * 100;
    } else {
       // If not scrollable, determine if we should show 0% or 100%
       if (scrollY > 0 && totalPageHeight > viewportHeight) {
           progressPercentage = 100;
       } else {
           progressPercentage = 0; // Otherwise show 0%
       }
    }
  
    // Ensure percentage is between 0 and 100
    progressPercentage = Math.min(100, Math.max(0, progressPercentage));
  
    // *** Update the WIDTH of the fill element ***
    fillElement.style.width = progressPercentage + '%';
  }
  
  // Add debounced event listeners for scroll and resize
  window.addEventListener('scroll', debounce(updateHorizontalProgress, 15), false);
  window.addEventListener('resize', debounce(updateHorizontalProgress, 50), false); // Update on resize too
  // Run once on load to set initial state
  window.addEventListener('load', updateHorizontalProgress);