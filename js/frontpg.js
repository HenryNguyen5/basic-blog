window.onload = () => {
	$( ".like" )
		.attr( "id", function ( arr ) {
			return this.id;
		} )
		.each( function () {
			addLike( this )
		} );
}

function addLike( post ) {
	console.log( post )
	$( "#" + post.id ).on( 'click', () => {
		$.get( '/blog/' + post.id + '/like', setLike )
	} );
}

function setLike( data ) {
	data = JSON.parse( data )

	if ( data.val === 0 ) {
		alert( "Can't like a post as the author!" )
	}
	$( "#" + data.postID ).text( 'Likes ' +
		data.val )
	console.log( 'liked!' )

}

function likeWarning() {
	alert( "Can't like a post as the author!" )
}
