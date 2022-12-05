// public/javasciprts/login.js
function login() {
    let txdata = {
        email: $('#email_PA_log').val(),
        password: $('#password_PA_log').val()
    };

    $.ajax({
        url: '/patient/logIn',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(txdata),
        dataType: 'json'
    })
    .done(function (data, textStatus, jqXHR) {
        localStorage.setItem("token", data.token);
        window.location.replace("/private/accountPatient.html");
    })
    .fail(function (jqXHR, textStatus, errorThrown) {
        $('#rxData').html(JSON.stringify(jqXHR, null, 2));
    });
}

$(function () {
    $('#logButton').click(login);
});