var map;
var service;
var infowindow;
var placeSearch, autocomplete;
var componentForm = {
	street_number: 'short_name',
	route: 'long_name',
	locality: 'long_name',
	administrative_area_level_1: 'short_name',
	country: 'long_name',
	postal_code: 'short_name'
};


function initialize() {
	var pyrmont = new google.maps.LatLng(-33.8665433,151.1956316);

	map = new google.maps.Map(document.getElementById('map'), {
		center: pyrmont,
		zoom: 15
	});
	var marker = new google.maps.Marker({ position : pyrmont, map : map});
}

function myclick() {
	var request = {
		bounds: map.getBounds(),
		query: $('#name').val(),
	};
	service = new google.maps.places.PlacesService(map);
	service.textSearch(request, callback);
}

var marker = []
var info = []
function callback(results, status) {
	if(status == google.maps.places.PlacesServiceStatus.OK) {
		$.post('googleapi', {'json':JSON.stringify(results)}, function(data,status){});
		for(let i =0; i<results.length; i++) {
			marker[i] = new google.maps.Marker({position : results[i].geometry.location, map:map});
			marker[i].setLabel(results[i].name);
			info[i] = new google.maps.InfoWindow({ content:results[i].name });
			marker[i].addListener('click', function() { info[i].open(map,marker[i]); }); 
		}
	}
} 

function initAutocomplete() {
	autocomplete = new google.maps.places.Autocomplete(
			(document.getElementById('autocomplete')), {types: ['geocode']});
	autocomplete.addListener('place_changed', fillInAddress);
}
var place;
var places = [];
function fillInAddress() {
	// Get the place details from the autocomplete object.
	place = autocomplete.getPlace();
	map.setCenter(place.geometry.location);
	$.post('googleapi', {'json':JSON.stringify(place)}, function(data, status){});

	for (var component in componentForm) {
		document.getElementById(component).value = '';
		document.getElementById(component).disabled = false;
	}

	// Get each component of the address from the place details
	// and fill the corresponding field on the form.
	for (var i = 0; i < place.address_components.length; i++) {
		var addressType = place.address_components[i].types[0];
		if (componentForm[addressType]) {
			var val = place.address_components[i][componentForm[addressType]];
			document.getElementById(addressType).value = val;
		}
	}
}
function geolocate() {
	if (navigator.geolocation) {
		navigator.geolocation.getCurrentPosition(function(position) {
			var geolocation = {
				lat: position.coords.latitude,
				lng: position.coords.longitude
			};
			var circle = new google.maps.Circle({
				center: geolocation,
				radius: position.coords.accuracy
			});
			autocomplete.setBounds(circle.getBounds());
		});
	}
}

function start() {
	places[0] = place;
	new google.maps.Marker({position:place.geometry.location, map:map});
}
function end() {
	places[1] = place;
	new google.maps.Marker({position:place.geometry.location, map:map});
}
function waypoint() {
	places.append(place);
}
function find() {
	var	directionsDisplay = new google.maps.DirectionsRenderer();
	var directionsService = new google.maps.DirectionsService();
	directionsDisplay.setMap(map);

	var request = {
		origin: places[0].geometry.location,
		destination: places[1].geometry.location,
		travelMode: 'TRANSIT'
	};
	directionsService.route(request, function(result, status) {
		if (status == 'OK') directionsDisplay.setDirections(result);
	});
}

$(function() {
	initialize();
	initAutocomplete();
})

