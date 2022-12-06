// public/javasciprts/account.js

let Data;

$(function () {
    $('#select_patient').change(Get_Chart);
    read_all_patient()
});

function read_all_patient() {
    $.ajax({
        url: '/physician/read_all_patient',
        method: 'GET',
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
            }, {})

            for (let i = 0; i < res.First_name.length; i++) {
                var name = res.First_name[i]
                var device_sn = res.device_sn[i]
                let Reports= `<div style="margin: auto; height: 40vh; width: 80vh;">
                    <h1>${name} - Weekly Summary View </h1>
                    <canvas id="${name}-Report"></canvas>
                </div><br><br><br>`
                let ChartID = `${name}-Report`
                $("#Show_All_Patient").append(Reports);
                Get_Chart(device_sn, ChartID)
              }
            console.log(res);
        })
        .fail(function (jqXHR, textStatus, errorThrown) {
            window.location.replace("display.html");
        });
}

function Get_Chart(Device_SN, ChartID){
    weekly_report(Device_SN, ChartID);
}

function weekly_report(Device_SN, ChartID) {
    let txdata = {
        device_sn: Device_SN,
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

            plot_bar_chart(res, ChartID);
        })
        .fail(function (data, textStatus, jqXHR) {
            $('#rxData').html(JSON.stringify(data, null, 2));
        });

    function plot_bar_chart(res, ChartID) {
        let HR_arr = res.HR;
        let SPO2_arr = res.SPO2;
        console.log(res);
        //bar chart
        var ctxB = document.getElementById(ChartID).getContext('2d');
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