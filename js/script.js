var c = document.getElementById("rainbow-matrix");
var ctx = c.getContext("2d");

//making the canvas full screen
c.height = window.innerHeight;
c.width = window.innerWidth;

//english characters
var message = "V2FrZSB1cCwgcHduaWVzLi4uClRoZSB3b3JsZCBoYXMgeW91CmZvbGxvdyB0aGUgYmx1ZSBwd25pZS4KS25vY2ssIGtub2NrLCBwd25pZXMuIA==";
//converting the string into an array of single characters
message = message.split("");

var font_size = 15;
var columns = Math.floor(c.width/font_size); //number of columns for the rain
//an array of drops - one per column
var drops = [];
//x below is the x coordinate
//1 = y co-ordinate of the drop(same for every drop initially)
for(var x = 0; x < columns; x++)
	drops[x] = c.height; 

//drawing the characters
function draw()
{
	//Black BG for the canvas
	//translucent BG to show trail
	ctx.fillStyle = "rgba(104, 78, 255, .3)";
	ctx.fillRect(0, 0, c.width, c.height);
	
	ctx.fillStyle = "rgba(255,123,245,.7)"; //green text
	ctx.font = font_size + "px system-ui";
	//looping over drops
	for(var i = 0; i < drops.length; i++)
	{
		//a random character to print
		var text = message[Math.floor(Math.random()*message.length)];
		//x = i*font_size, y = value of drops[i]*font_size
		ctx.fillText(text, i*font_size, drops[i]*font_size);
		
		//sending the drop back to the top randomly after it has crossed the screen
		//adding a randomness to the reset to make the drops scattered on the Y axis
		if(drops[i]*font_size > c.height && Math.random() > 0.975)
			drops[i] = 0;
		
		//incrementing Y coordinate
		drops[i]++;
	}
}

setInterval(draw, 33);
