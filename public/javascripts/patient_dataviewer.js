// public/javasciprts/account.js

let Data;

$(function () {
    $('#btnLogOut').click(logout);
    $('#btnUpdate').click(Update_Info);

    $.ajax({
        url: '/patient/status',
        method: 'GET',
        headers: { 'x-auth': window.localStorage.getItem("token") },
        dataType: 'json'
    })
        .done(function (data, textStatus, jqXHR) {
            // $('#rxData').html(JSON.stringify(data, null, 2));
            weekly_report(data[0]);
            daily_report(data[0]);
        })
        .fail(function (jqXHR, textStatus, errorThrown) {
            window.location.replace("display.html");
        });
});

function weekly_report(Data) {
    let txdata = {
        device_sn: Data.device_sn,
        current_date: new Date(),
    };
    $.ajax({
        url: '/api/weekly_patient_data',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(txdata),
        dataType: 'json'
    })
        .done(function (data, textStatus, jqXHR) {
            const res = data.reduce((a, b) => {
                for (let i in b) {
                    if (!a[i]) {
                        a[i] = [];
                    }
                    a[i].push(b[i]);
                }

                return a;
            }, {});

            plot_bar_chart(res);
        })
        .fail(function (data, textStatus, jqXHR) {
            $('#rxData').html(JSON.stringify(data, null, 2));
        });

    function plot_bar_chart(res) {
        let HR_arr = res.HR;
        let SPO2_arr = res.SPO2;
        console.log(res);
        //bar chart
        var ctxB = document.getElementById("barChart").getContext('2d');
        var myBarChart = new Chart(ctxB, {
            type: 'bar',
            data: {
                labels: ['HR-Mean', 'spO2-Mean', 'HR-Min', 'spO2-Min', 'HR-Max', 'spO2-Max'],
                datasets: [{
                    label: 'Sensor Values',
                    data: [mean(HR_arr), mean(SPO2_arr), min(HR_arr), min(SPO2_arr), max(HR_arr), max(SPO2_arr)],
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.2)',
                        'rgba(54, 162, 235, 0.2)',
                        'rgba(255, 205, 86, 0.2)',
                        'rgba(75, 192, 192, 0.2)',
                        'rgba(54, 162, 235, 0.2)',
                        'rgba(153, 102, 255, 0.2)',
                    ],
                    borderColor: [
                        'rgba(255,99,132,1)',
                        'rgba(54, 162, 235, 1)',
                        'rgb(255, 205, 86)',
                        'rgb(75, 192, 192)',
                        'rgb(54, 162, 235)',
                        'rgb(153, 102, 255)',
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    yAxes: [{
                        ticks: {
                            beginAtZero: true
                        }
                    }]
                }
            }
        });
    };
};

function daily_report(Data) {
    let txdata = {
        device_sn: Data.device_sn,
        current_date: new Date(),
    };
    $.ajax({
        url: '/api/daily_patient_data',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(txdata),
        dataType: 'json'
    })
        .done(function (data, textStatus, jqXHR) {
            const res = data.reduce((a, b) => {
                for (let i in b) {
                    if (!a[i]) {
                        a[i] = [];
                    }
                    a[i].push(b[i]);
                }

                return a;
            }, {});

            line_chart(res);
        })
        .fail(function (data, textStatus, jqXHR) {
            $('#rxData').html(JSON.stringify(data, null, 2));
        });
    //line
    function line_chart(Data) {
        console.log(Data);
        var ctxL = document.getElementById("lineChart").getContext('2d');
        var myLineChart = new Chart(ctxL, {
            type: 'line',
            data: {
                labels: Data.published_at,
                datasets: [{
                    label: "HR",
                    data: Data.HR,
                    backgroundColor: [
                        'rgba(105, 0, 132, .2)',
                    ],
                    borderColor: [
                        'rgba(200, 99, 132, .7)',
                    ],
                    borderWidth: 2
                },
                {
                    label: "SPO2",
                    data: Data.SPO2,
                    backgroundColor: [
                        'rgba(0, 137, 132, .2)',
                    ],
                    borderColor: [
                        'rgba(0, 10, 130, .7)',
                    ],
                    borderWidth: 2
                }
                ]
            },
            options: {
                responsive: true,
                scales: {
                    label: {
                        type: 'time',
                        time: {
                            unit: 'month'
                        }
                    }
                }
            }
        });
    }
}

function mean(Data_Arr) {
    const filtered = Data_Arr.filter(item => item !== 0);
    const sum = filtered.reduce((a, b) => a + b);
    const avg = sum / filtered.length;
    console.log(avg);
    return Math.round(avg);
}

function min(Data_Arr) {
    const filtered = Data_Arr.filter(item => item !== 0);
    Min = Math.min.apply(Math, filtered);
    console.log(Min);
    return Min;
}

function max(Data_Arr) {
    const filtered = Data_Arr.filter(item => item !== 0);
    Max = Math.max.apply(Math, filtered);
    console.log(Max);
    return Max;
}

function logout() {
    localStorage.removeItem("token");
    window.location.replace("index.html");
}

function Update_Info() {
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