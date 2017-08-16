function signInCallback(authResult) {
    if (authResult['code']) {
        // Hide the sign-in button now that the user is authorized
        $('#signinButton').attr('style', 'display: none');
        var _csrf_token = $('#csrf').val();
        var data = {
            code: authResult['code'],
            _csrf_token: _csrf_token
        }
        $.ajax({
            type: 'POST',
            url: '/gconnect',
            //processData: false,
            data: data,
            dataType: "json",
            //contentType: 'application/octet-stream; charset=utf-8',
            success: function(result) {
                // Handle or verify the server response if necessary.
                if (result) {
                    displayLoggedInUserInfo(result);
                    // setTimeout(function() {
                    //     window.location.href = "/restaurant";
                    // }, 4000);
                } else if (authResult['error']) {
                    console.log('There was an error: ' + authResult['error']);
                } else {
                    $('#result').html('Failed to make a server-side call. Check your configuration and console.');
                }
            }
        });
    }
}

function loadFBSDK() {
    window.fbAsyncInit = function() {
        FB.init({
            appId: '809901365835405',
            cookie: true, // enable cookies to allow the server to access 
            // the session
            xfbml: true, // parse social plugins on this page
            version: 'v2.8' // use version 2.8
        });
    };
    // Load the SDK asynchronously
    (function(d, s, id) {
        var js, fjs = d.getElementsByTagName(s)[0];
        if (d.getElementById(id)) return;
        js = d.createElement(s);
        js.id = id;
        js.src = "//connect.facebook.net/en_US/sdk.js";
        fjs.parentNode.insertBefore(js, fjs);
    }(document, 'script', 'facebook-jssdk'));
    // Here we run a very simple test of the Graph API after login is
    // successful.  See statusChangeCallback() for when this call is made.
}

function sendTokenToServer() {
    var access_token = FB.getAuthResponse()['accessToken'];
    var _csrf_token = $('#csrf').val();
    var data = {
        access_token: access_token,
        _csrf_token: _csrf_token
    }
    FB.api('/me', function(response) {
        $.ajax({
            type: 'POST',
            url: '/fbconnect',
            //processData: false,
            data: data,
            dataType: "json",
            //contentType: 'application/octet-stream; charset=utf-8',
            success: function(result) {
                // Handle or verify the server response if necessary.
                if (result) {
                    displayLoggedInUserInfo(result);
                    // setTimeout(function() {
                    //     window.location.href = "/restaurant";
                    // }, 4000);
                } else {
                    $('#result').html('Failed to make a server-side call. Check your configuration and console.');
                }
            }
        });
    });
}

function displayLoggedInUserInfo(userInfo) {
    $('#login-panel').addClass('hide');
    $('#user-info').removeClass('hide');
    $('.profile-img').attr('src', userInfo.picture);
    $('.profile-name').text(userInfo.username);
    setTimeout(function() {
        window.location.href = "/";
    }, 2000);
}