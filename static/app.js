// Close flash messages after 3 seconds
setTimeout(function () { bootstrap.Alert.getOrCreateInstance(document.querySelector(".alert")).close(); }, 3000)

// Timer display for session duration
String.prototype.toHHMMSS = function () {
    var sec_num = parseInt(this, 10); // don't forget the second param
    var hours = Math.floor(sec_num / 3600);
    var minutes = Math.floor((sec_num - (hours * 3600)) / 60);
    var seconds = sec_num - (hours * 3600) - (minutes * 60);

    if (hours < 10) { hours = "0" + hours; }
    if (minutes < 10) { minutes = "0" + minutes; }
    if (seconds < 10) { seconds = "0" + seconds; }
    return hours + ':' + minutes + ':' + seconds;
}

// Refresh page every minute
function display_session_timer() {
    var refresh = 1000; // Refresh rate in milli seconds
    setTimeout('calc_session_timer()', refresh)
}

function calc_session_timer() {
    var end = new Date(ts);
    var now = new Date();
    
    // Session has ended, reload page
    if (ts != 0 && ts < now) {
        location.reload();
        return;
    }
    
    // Calculate remaining time and display
    var duration = new Date(0);
    duration.setSeconds((end - now) / 1000);
    var timeString = duration.toISOString().substring(11, 19);
    document.getElementById('session').value = timeString;
    // Kick off the timer again
    display_session_timer();
}

// Kick off the timer
calc_session_timer();
