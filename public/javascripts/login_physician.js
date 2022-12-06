// public/javasciprts/login.js
function login() {
    let txdata = {
        email: $('#email_PH_log').val(),
        password: $('#password_PH_log').val()
    };

    $.ajax({
        url: '/physician/logIn',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(txdata),
        dataType: 'json'
    })
    .done(function (data, textStatus, jqXHR) {
        localStorage.setItem("token", data.token);
        window.location.replace("/private/accountPhysician.html");
    })
    .fail(function (jqXHR, textStatus, errorThrown) {
        $('#rxData').html(JSON.stringify(jqXHR, null, 2));
    });
}

$(function () {
    $('#logButton').click(login);
});