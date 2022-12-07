// public/javasciprts/account.js

let Data;

$(function (){
    $('#btnUpdate').click(Update_Info);

    $.ajax({
        url: '/physician/status',
        method: 'GET',
        headers: { 'x-auth' : window.localStorage.getItem("token") },
        dataType: 'json'
    })
    .done(function (data, textStatus, jqXHR) {
        // $('#rxData').html(JSON.stringify(data, null, 2));
        $('#first_name').val(data[0].First_name);
        $('#last_name').val(data[0].Last_name);
        $('#email').val(data[0].Email);
        $('#physician').val(data[0].physician);
        $('.font-weight-bold').html(data[0].First_name);
        $('.text-black-50').html(data[0].Email);
        Data = data[0];
    })
    .fail(function (jqXHR, textStatus, errorThrown) {
        window.location.replace("../display.html");
    });
});

function Update_Info(){
    let txdata = {
        _id: Data._id,
        First_name: $('#first_name').val(),
        Last_name: $('#last_name').val(),
        Email: $('#email').val(),
        physician: $('#physician').val(),
    };

    $.ajax({
        url: '/patient/update_info',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(txdata),
        dataType: 'json'
    })
    .done(function (data, textStatus, jqXHR) {
        $('#rxData').html(data.message);
    })
    .fail(function (data, textStatus, jqXHR) {
        $('#rxData').html(Jdata.message);
    });
}