//Check overlap with navbar
$(document).ready(function() {
    const formBox = $(".app-form-box");
    if (formBox.length) {
        const navbarBottom = 77;
        const formBoxTop = formBox.offset().top;
        if (formBoxTop < navbarBottom) {
            const pixelShift = navbarBottom - formBoxTop;
            formBox.css("margin-top", pixelShift.toString() + "px");
        }
    }
});

//Remove favourited plan for favourites.html
$(".remove-fav-btn").click(function(event) {
    const planDiv = $(event.target).parent().parent().parent()
    console.log(planDiv.html());
    planDiv.html("Plan removed from favourites.");
});

//Favourite button
$(".fav-btn").click(function(event) {
    if ($(this).hasClass("fav-btn-checked")) {
        $(this).removeClass("fav-btn-checked").addClass("fav-btn-unchecked");
        const url = '/background_process_remove_favourite/' + event.target.id;
    $.getJSON(url,
        function(data) {
      //do nothing
    });
    return false;
    } else {
        $(this).removeClass("fav-btn-unchecked").addClass("fav-btn-checked");
        const url = '/background_process_favourite/' + event.target.id;
    $.getJSON(url,
        function(data) {
      //do nothing
    });
    return false;
    }
});

$(".read-check").click(function(event) {
    const url = '/background_process_read_announcement/' + event.target.id;
    $(this).remove();
    $.getJSON(url, function(data) {
       //do nothing
    });
    return false;
});

//Back button
function backButton() {
    window.history.back();
}

//Back to top button
function backToTop() {
    $('html, body').animate({scrollTop:0}, '300');
}

$(document).ready(function() {
    const btn = $('#back-to-top');
    $(window).scroll(function() {
        if ($(window).scrollTop() > 300) {
            btn.addClass("show");
        } else {
            btn.removeClass("show");
        }
    })
})