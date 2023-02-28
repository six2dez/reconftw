let arrow = document.querySelectorAll(".arrow");

for (var i = 0; i < arrow.length; i++) {
  arrow[i].addEventListener("click", (e) => {
    let arrowParent = e.target.parentElement.parentElement; //selecting main parent of arrow
    console.log(arrowParent);
    arrowParent.classList.toggle("showMenu");
  });
}

let sidebar = document.querySelector(".sidebar");
let sidebarBtn = document.querySelector(".bx-menu");
sidebarBtn.addEventListener("click", () => {
  sidebar.classList.toggle("close");
});

function menuToggle() {
  const toggleMenu = document.querySelector(".menu");
  toggleMenu.classList.toggle("active");
}

let modalId = $("#image-gallery");

$(document).ready(function () {
  loadGallery(true, "a.thumbnail");

  //This function disables buttons when needed
  function disableButtons(counter_max, counter_current) {
    $("#show-previous-image, #show-next-image").show();
    if (counter_max === counter_current) {
      $("#show-next-image").hide();
    } else if (counter_current === 1) {
      $("#show-previous-image").hide();
    }
  }

  /**
   *
   * @param setIDs        Sets IDs when DOM is loaded. If using a PHP counter, set to false.
   * @param setClickAttr  Sets the attribute for the click handler.
   */

  function loadGallery(setIDs, setClickAttr) {
    let current_image,
      selector,
      counter = 0;

    $("#show-next-image, #show-previous-image").click(function () {
      if ($(this).attr("id") === "show-previous-image") {
        current_image--;
      } else {
        current_image++;
      }

      selector = $('[data-image-id="' + current_image + '"]');
      updateGallery(selector);
    });

    function updateGallery(selector) {
      let $sel = selector;
      current_image = $sel.data("image-id");
      $("#image-gallery-title").text($sel.data("title"));
      $("#image-gallery-image").attr("src", $sel.data("image"));
      disableButtons(counter, $sel.data("image-id"));
    }

    if (setIDs == true) {
      $("[data-image-id]").each(function () {
        counter++;
        $(this).attr("data-image-id", counter);
      });
    }
    $(setClickAttr).on("click", function () {
      updateGallery($(this));
    });
  }
});

// build key actions
$(document).keydown(function (e) {
  switch (e.which) {
    case 37: // left
      if (
        (modalId.data("bs.modal") || {})._isShown &&
        $("#show-previous-image").is(":visible")
      ) {
        $("#show-previous-image").click();
      }
      break;

    case 39: // right
      if (
        (modalId.data("bs.modal") || {})._isShown &&
        $("#show-next-image").is(":visible")
      ) {
        $("#show-next-image").click();
      }
      break;

    default:
      return; // exit this handler for other keys
  }
  e.preventDefault(); // prevent the default action (scroll / move caret)
});

// Data Table Subdomains
$(document).ready(function () {
  $("#subdomains").DataTable({
    bPaginate: true,
    bLengthChange: false,
    bFilter: true,
    bInfo: true,
    bAutoWidth: true,
  });
});

// Data Table Cloud_Assets
$(document).ready(function () {
  $("#cloud_assets").DataTable({
    bPaginate: false,
    bLengthChange: false,
    bFilter: false,
    bInfo: false,
    bAutoWidth: true,
  });
});

// Data Table Screenshot
$(document).ready(function () {
  $("#screenshotss").DataTable({
    bPaginate: true,
    bLengthChange: false,
    bFilter: true,
    bInfo: true,
    bAutoWidth: true,
  });
});

// Data Table Nuclei_Info
$(document).ready(function () {
  $("#nuclei_info").DataTable({
    bPaginate: true,
    bLengthChange: false,
    bFilter: true,
    bInfo: true,
    bAutoWidth: true,
  });
});

// Data Table Nuclei_Low
$(document).ready(function () {
  $("#nuclei_low").DataTable({
    bPaginate: false,
    bLengthChange: false,
    bFilter: false,
    bInfo: false,
    bAutoWidth: true,
  });
});

// Data Table Nuclei_Medium
$(document).ready(function () {
  $("#nuclei_medium").DataTable({
    bPaginate: false,
    bLengthChange: false,
    bFilter: false,
    bInfo: false,
    bAutoWidth: true,
  });
});

// Data Table Nuclei_High
$(document).ready(function () {
  $("#nuclei_high").DataTable({
    bPaginate: false,
    bLengthChange: false,
    bFilter: false,
    bInfo: false,
    bAutoWidth: true,
  });
});

// Data Table Nuclei_Critical
$(document).ready(function () {
  $("#nuclei_critical").DataTable({
    bPaginate: false,
    bLengthChange: false,
    bFilter: false,
    bInfo: false,
    bAutoWidth: true,
  });
});

$(document).ready(function () {
  $("#js_livelinks").DataTable({
    bPaginate: true,
    bLengthChange: false,
    bFilter: true,
    bInfo: true,
    bAutoWidth: true,
  });
});

$(document).ready(function () {
  $("#url_extract_js").DataTable({
    bPaginate: true,
    bLengthChange: false,
    bFilter: true,
    bInfo: true,
    bAutoWidth: true,
  });
});

$(document).ready(function () {
  $("#js_endpoints").DataTable({
    bPaginate: true,
    bLengthChange: false,
    bFilter: true,
    bInfo: true,
    bAutoWidth: true,
  });
});

$(document).ready(function () {
  $("#js_secrets").DataTable({
    bPaginate: true,
    bLengthChange: false,
    bFilter: true,
    bInfo: true,
    bAutoWidth: true,
  });
});

$(document).ready(function () {
  $(".web_dicts").DataTable({
    bPaginate: true,
    bLengthChange: false,
    bFilter: true,
    bInfo: true,
    bAutoWidth: true,
  });
});

$(document).ready(function () {
  $("#fuzzing_paths").DataTable({
    bPaginate: true,
    bLengthChange: false,
    bFilter: true,
    bInfo: true,
    bAutoWidth: true,
  });
});

$(document).ready(function () {
  var imageSources = [
    "https://images.pexels.com/photos/837500/pexels-photo-837500.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
    "https://images.pexels.com/photos/20790/pexels-photo.jpg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
    "https://images.pexels.com/photos/41180/animal-blue-pattern-danger-41180.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
    "https://images.pexels.com/photos/137610/pexels-photo-137610.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
    "https://images.pexels.com/photos/753266/pexels-photo-753266.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
    "https://images.pexels.com/photos/1000654/pexels-photo-1000654.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
    "https://images.pexels.com/photos/1000653/pexels-photo-1000653.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
    "https://images.pexels.com/photos/982229/pexels-photo-982229.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
    "https://images.pexels.com/photos/982229/pexels-photo-982229.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
  ];
  var imageSrc; // Used for left and right arrow in full screen image viewer
  var currentPage = 1;
  var numOfPages = Math.ceil(imageSources.length / 4);
  //populate page numbers
  for (var j = 1; j <= numOfPages; j++) {
    $("#pages").append(
      "<a class='galleryButton' value='" + j + "'>" + j + "</a>"
    );
  }
  //populate first row of images
  $(".galleryButton").first().addClass("selectedPage");
  var thePage = $(".galleryButton").first(); //Used for showing selected page when clicking next

  for (var i = 0; i < 4; i++) {
    var html =
      '<img src="' + imageSources[i] + '" class="galleryImage" alt="nothing">';
    $("#gallery").append(html);
  }

  //click functions
  $(".galleryButton").on("click", galleryButtonClick);
  $("#next").on("click", nextClick);
  $("#prev").on("click", prevClick);
  $(".galleryImage").on("click", galleryImageClick);
  $(".closebtn").on("click", closeOverlay);

  function runAnimation(direction, isNext, passedPage) {
    $(".galleryButton,#next,#prev").off("click");
    $("#gallery").addClass(direction);
    if (isNext == "next") {
      setTimeout(function () {
        pageHandler(currentPage, 1);
      }, 1000);
    } else if (isNext == "prev") {
      setTimeout(function () {
        pageHandler(currentPage, -1);
      }, 1000);
    } else if (isNext == false) {
      setTimeout(function () {
        pageHandler(passedPage, 0);
      }, 1000);
    }

    setTimeout(function () {
      $("#gallery").removeClass(direction);
      $(".galleryButton").on("click", galleryButtonClick);
      $("#next").on("click", nextClick);
    }, 2000);
  }

  function pageHandler(passedPage, pageAddition) {
    var page = passedPage + pageAddition;
    currentPage = page;
    if (currentPage == 1) {
      $("#prev").css("display", "none");
    } else {
      $("#prev").css("display", "initial");
    }
    if (currentPage == numOfPages) {
      $("#next").css("display", "none");
    } else {
      $("#next").css("display", "initial");
    }
    var startingNumber = getStartingNumber(page);
    $("#gallery").html("");
    for (var i = startingNumber; i < startingNumber + 4; i++) {
      var html = '<img src="' + imageSources[i] + '" class="galleryImage">';
      $("#gallery").append(html);
    }
    //Dont show broken link image.
    $(".galleryImage").on("error", function () {
      $(this).hide();
    });
    $(".galleryImage").on("click", galleryImageClick);
  }
  function getStartingNumber(page) {
    /*1 = 0 2 = 4 3 = 8 4 = 12 5 = 16*/
    var startingNumber = 0;
    if (page != 1) {
      for (var i = 1; i < page; i++) {
        startingNumber = startingNumber + 4;
      }
    }
    return startingNumber;
  }

  //galleryButton handler
  function galleryButtonClick(event) {
    $(".galleryButton").removeClass("selectedPage");
    $(event.currentTarget).addClass("selectedPage");
    thePage = event.currentTarget;
    var passedPage = parseInt($(event.currentTarget).attr("value"));
    if (passedPage > currentPage) {
      runAnimation("right2left", false, passedPage);
    } else if (passedPage < currentPage) {
      runAnimation("left2right", false, passedPage);
    }
  }

  //next button handler
  function nextClick() {
    if (currentPage != numOfPages) {
      $(".galleryButton").removeClass("selectedPage");
      $(thePage).next().addClass("selectedPage");
      thePage = $(thePage).next();
      runAnimation("right2left", "next", currentPage);
    }
  }

  //prev button handler
  function prevClick() {
    if (currentPage != 1) {
      $(".galleryButton").removeClass("selectedPage");
      $(thePage).prev().addClass("selectedPage");
      thePage = $(thePage).prev();
      runAnimation("left2right", "prev", currentPage);
    }
  }

  function galleryImageClick() {
    $(".overlay-content").html("");
    $(".overlay").css("height", "100%");
    var image = '<img src="' + this.src + '" class="overlayImage">';
    imageSrc = this.src;
    $(".overlay-content").append(
      '<i class="fas fa-angle-left" id="arrowLeft"></i>'
    );
    $("#arrowLeft").on("click", leftArrow);
    $(".overlay-content").append(image);
    $(".overlay-content").append(
      '<i class="fas fa-angle-right" id="arrowRight"></i>'
    );
    $("#arrowRight").on("click", rightArrow);
  }

  function closeOverlay() {
    $(".overlay").css("height", "0");
    $(".overlay-content").html("");
  }

  function leftArrow() {
    var currentPosition = imageSources.indexOf(imageSrc);
    if (currentPosition != 0) {
      var image =
        '<img src="' +
        imageSources[currentPosition - 1] +
        '" class="overlayImage">';
      $(".overlay-content").html("");
      $(".overlay-content").append(
        '<i class="fas fa-angle-left" id="arrowLeft"></i>'
      );
      $(".overlay-content").append(image);
      $(".overlay-content").append(
        '<i class="fas fa-angle-right" id="arrowRight"></i>'
      );
      imageSrc = imageSources[currentPosition - 1];
      $("#arrowLeft").on("click", leftArrow);
      $("#arrowRight").on("click", rightArrow);
    }
  }

  function rightArrow(image) {
    var currentPosition = imageSources.indexOf(imageSrc);
    if (currentPosition != imageSources.length - 1) {
      var image =
        '<img src="' +
        imageSources[currentPosition + 1] +
        '" class="overlayImage">';
      $(".overlay-content").html("");
      $(".overlay-content").append(
        '<i class="fas fa-angle-left" id="arrowLeft"></i>'
      );
      $(".overlay-content").append(image);
      $(".overlay-content").append(
        '<i class="fas fa-angle-right" id="arrowRight"></i>'
      );
      imageSrc = imageSources[currentPosition + 1];
      $("#arrowLeft").on("click", leftArrow);
      $("#arrowRight").on("click", rightArrow);
    }
  }
});

// Back to top
var amountScrolled = 200;
var amountScrolledNav = 25;

$(window).scroll(function () {
  if ($(window).scrollTop() > amountScrolled) {
    $("button.back-to-top").addClass("show");
  } else {
    $("button.back-to-top").removeClass("show");
  }
});

$("button.back-to-top").click(function () {
  $("html, body").animate(
    {
      scrollTop: 0,
    },
    100
  );
  return false;
});
