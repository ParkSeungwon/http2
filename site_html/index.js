function b64e(s) {
	return window.btoa(unescape(encodeURIComponent(s)));
}
function b64d(s) {
	return decodeURIComponent(escape(window.atob(s)));
}
function on_submit() {
	$("textarea").val(b64e($("textarea").val()));
	$("input[name='title']").val(b64e($("input[name='title']").val()));
}
function on_click() {
	$('#frame').hide();
	$('#edit').show();
}

function cancel() {
	$('#frame').show();
	$('#edit').hide();
}
function set_height(h) {
	$('#if2').height(h);
}
function resize() {
//	obj.style.height = obj.contentWindow.document.body.scrollHeight + 'px'
	alert(JSON.stringify($('#if2').contents()));
	var fr = $('#if2');
	alert('hello');
	for(var i=0; i<0; i++) {
		alert('scroll' + fr.get(0).scrollHeight + 'inner' + fr.innerHeight()
			+ 'client' + fr.get(0).clientHeight + 'height' + fr.height() + 'contents'
		+ fr.contents().height());
		fr.height(fr.height() + 100);
	}
//	$('#if2').height($('#if2').contents().height() + 15);
	alert(true);
	alert(/*JSON.stringify*/($('#if2').contents()[0].height()));
	alert(/*JSON.stringify*/($('#if2').children()[0].height()));
//	alert($('#if2').scrollHeight);//.document.body.scrollHeight + 'px');
}
$(function on_ready() {
	$('h1').text(b64d($('h1').text()));
	$("input[name='title']").val(b64d($("input[name='title']").val()));
	$('textarea').val(b64d($('textarea').val()));
	new Vue({
		el : '#app-6',
		data : {
			message : '안녕하세요 Vue'
		}
	})
});

