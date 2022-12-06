// public/javasciprts/webstorage.js

let firstInput=document.getElementById("First_name_PA");
let lastInput=document.getElementById("Last_name_PA");
let emailInput=document.getElementById("Email_PA");
let passInput=document.getElementById("Password_PA");
let passConInput=document.getElementById("Con_Password_PA");
let submitInput=document.getElementById("Submit_PA");
let resetInput=document.getElementById("Reset_PA");
let errorOutput=document.getElementById("formErrors");
let re=/^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,5}$/;
let relower=/(.*[a-z].*)/;
let reupper=/(.*[A-Z].*)/;
let redigit=/(.*\d.*)/;
/*
function createStudent() {
    // data validation
    let txdata = {
        First_name:    $("First_name_PA").val(),
        Last_name:     $("Last_name_PA").val(),
        Email:         $("Email_PA").val(),
        password:      $("Password_PA").val(),
    };

    $.ajax({
        url: '/patient/create',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(txdata),
        dataType: 'json'
    })
    .done(function (data, textStatus, jqXHR) {
        $('#rxData').html(JSON.stringify(data, null, 2));
    })
    .fail(function (data, textStatus, jqXHR) {
        $('#rxData').html(JSON.stringify(data, null, 2));
    });
}

$(function () {
    $('#btnLogIn').click(createStudent);
});
*/

function formValidate(){
    errorOutput.innerHTML="";
    
    firstInput.style.setProperty("border","1px solid #aaa");
    lastInput.style.setProperty("border","1px solid #aaa");
    emailInput.style.setProperty("border","1px solid #aaa");
    passInput.style.setProperty("border","1px solid #aaa");
    passConInput.style.setProperty("border","1px solid #aaa");
    errorOutput.style.setProperty("display","none");


//Checking if first name is valid. It cannot be an empty string or contain a digit.

    result=redigit.exec(firstInput.value);
    if(firstInput.value.length==0 || result!=null ){
        errorOutput.innerHTML="<ul><li>Missing first name and cannot have digits.</li></ul>";
        firstInput.style.setProperty("border","2px solid red");
        errorOutput.style.setProperty("display","block");
    } 
    else{
        errorOutput.innerHTML+="";
    }
//Checking if last name is valid. It cannot be an empty string or contain a digit.

    result=redigit.exec(lastInput.value);
    if(lastInput.value.length==0 || result!=null){
        errorOutput.innerHTML="<ul><li>Missing last name and cannot have digits.</li></ul>";
        lastInput.style.setProperty("border","2px solid red");
        errorOutput.style.setProperty("display","block");
    } 
    else{
        errorOutput.innerHTML+="";
    }

//Checking if email is valid.

    result=re.exec(emailInput.value);
    if(result==null||emailInput.value.length==0){

        errorOutput.innerHTML+="<ul><li>Invalid or missing email address.</li></ul>";
        emailInput.style.setProperty("border","2px solid red");
        errorOutput.style.setProperty("display","block");
        
    }
    else{
        errorOutput.innerHTML+="";
    }

//Checking if password has the correct length.

    if(passInput.value.length<8 || passInput.value.length>20){

        errorOutput.innerHTML+="<ul><li>Password must be between 8 and 20 characters.</li></ul>";
        passInput.style.setProperty("border","2px solid red");
        errorOutput.style.setProperty("display","block");
    }
    else{
        errorOutput.innerHTML+="";
    }


    result=relower.exec(passInput.value);
    if(result==null){

        errorOutput.innerHTML+="<ul><li>Password must contain at least one lowercase character.</li></ul>";
        passInput.style.setProperty("border","2px solid red");
        errorOutput.style.setProperty("display","block");
    }
    else{
        errorOutput.innerHTML+="";
    }

    result=reupper.exec(passInput.value);
    if(result==null){

        errorOutput.innerHTML+="<ul><li>Password must contain at least one uppercase character.</li></ul>";
        passInput.style.setProperty("border","2px solid red");
        errorOutput.style.setProperty("display","block");
    }
    else{
        errorOutput.innerHTML+="";
    }

    result=redigit.exec(passInput.value);
    if(result==null){

        errorOutput.innerHTML+="<ul><li>Password must contain at least one digit.</li></ul>";
        passInput.style.setProperty("border","2px solid red");
        errorOutput.style.setProperty("display","block");
    }
    else{
        errorOutput.innerHTML+="";
    }

    if(passInput.value!=passConInput.value){

        errorOutput.innerHTML+="<ul><li>Password and confirmation password don't match.</li></ul>";
        passInput.style.setProperty("border","2px solid red");
        errorOutput.style.setProperty("display","block");
    }
    else{
        errorOutput.innerHTML+="";
    }

    if(errorOutput.innerHTML==""){

        let txdata = {
            First_name:    $("#First_name_PA").val(),
            Last_name:     $("#Last_name_PA").val(),
            Email:         $("#Email_PA").val(),
            password:      $("#Password_PA").val(),
        };
    
        $.ajax({
            url: '/patient/create',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(txdata),
            dataType: 'json'
        })
        .done(function (data, textStatus, jqXHR) {
            $('#rxData').html(data.message);
        })
        .fail(function (data, textStatus, jqXHR) {
            $('#rxData').html(data.msg);
        });

    }

    else{
       errorOutput.innerHTML+=""; 
    }

}

submitInput.addEventListener("click",formValidate,false);

function formReset(){
    firstInput.value="";    
    lastInput.value="";
    emailInput.value="";
    passInput.value="";
    passConInput.value="";
    errorOutput.value="";

    firstInput.style.setProperty("border","1px solid #aaa");
    lastInput.style.setProperty("border","1px solid #aaa");
    emailInput.style.setProperty("border","1px solid #aaa");
    passInput.style.setProperty("border","1px solid #aaa");
    passConInput.style.setProperty("border","1px solid #aaa");
    errorOutput.style.setProperty("display","none");

}
resetInput.addEventListener("click",formReset,false);

