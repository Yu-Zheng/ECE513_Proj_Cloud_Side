// public/javasciprts/patient_device.js

let Data;

$(function (){
    $('#btnLogOut').click(logout);
    $('#btnUpdate').click(Update_device);

    $.ajax({
        url: '/patient/status',
        method: 'GET',
        headers: { 'x-auth' : window.localStorage.getItem("token") },
        dataType: 'json'
    })
    .done(function (data, textStatus, jqXHR) {
        $('#device_name').val(data[0].device_name);
        $('#device_sn').val(data[0].device_sn);
        Data = data[0];
    })
    .fail(function (jqXHR, textStatus, errorThrown) {
        window.location.replace("display.html");
    });
});

function logout() {
    localStorage.removeItem("token");
    window.location.replace("index.html");
}

function Update_device(){
    if ($('#device_name').val() === "") {
        window.alert("invalid device name!");
        return;
    }
    if ($('#device_sn').val() === "") {
        window.alert("invalid device sn!");
        return;
    }
    if ($('#device_name').val() === "No Device") {
        window.alert("invalid device name!");
        return;
    }
    if ($('#device_sn').val() === "No Device") {
        window.alert("invalid device sn!");
        return;
    }

    let txdata = {
        _id: Data._id,
        device_name: $('#device_name').val(),
        device_sn: $('#device_sn').val()
    };

    $.ajax({
        url: '/patient/update_device',
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