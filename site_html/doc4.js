$(function() {
	$('button').click(function() {
		$.post("post-test", {abc : 123, day : 'mon'}, function(data, status) {
			alert("Data : " + data + "\nStatus : " + status);
		});
	});
});
