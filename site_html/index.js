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
function resize() {
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

