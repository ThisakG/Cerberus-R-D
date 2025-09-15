// Only randomize between left, center, and right at the bottom
function randomDogBottomPosition() {
  const dog = document.getElementById('dog-lottie');
  const positions = [
    {left: '24px', right: '', margin: '0'}, // bottom-left
    {left: '', right: '24px', margin: '0'}  // bottom-right
  ];
  const pos = positions[Math.floor(Math.random() * positions.length)];
  dog.style.left = pos.left;
  dog.style.right = pos.right;
  dog.style.marginLeft = pos.margin;
  dog.style.bottom = '24px';
  dog.style.top = '';
}
randomDogBottomPosition();

// Show the dog only after scrolling down 200px
window.addEventListener('scroll', function() {
  var dog = document.getElementById('dog-lottie');
  if (window.scrollY > 200) {
    dog.style.display = 'block';
  } else {
    dog.style.display = 'none';
  }
});