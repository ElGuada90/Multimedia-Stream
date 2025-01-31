const video = document.querySelector('video');
let lastTime = 0;

video.addEventListener('pause', () => {
    lastTime = video.currentTime;
});

        function rewind() {
            video.currentTime = Math.max(0, video.currentTime - 10);
        }

        function playPause() {
            if (video.paused) {
                const shouldPlay = confirm(`¿Deseas reproducir el video desde el último tiempo? (Último tiempo: ${lastTime.toFixed(2)}s)`);
                if (shouldPlay) {
                    video.currentTime = lastTime;
                    video.play();
                } else {
                    video.currentTime = 0; // Reinicia el video al inicio
                    video.play();
                }
            } else {
                video.pause();
            }
        }

        function forward() {
            video.currentTime = Math.min(video.duration, video.currentTime + 10);
        }

        function makeBig(){
            if (video.requestFullscreen) {
                video.requestFullscreen();
            } else if (video.mozRequestFullScreen) { // Para Firefox
                video.mozRequestFullScreen();
            } else if (video.webkitRequestFullscreen) { // Para Chrome, Safari y Opera
                video.webkitRequestFullscreen();
            } else if (video.msRequestFullscreen) { // Para Internet Explorer/Edge
                video.msRequestFullscreen();
            }
        }

        function makeSmall() {
            video.style.width = '50%';
            video.style.margin = '0 auto';
        }

        function makeNormal() {
            video.style.width = '100%';
            video.style.margin = '0';
        }

    
        const headers = document.querySelectorAll('.accordion-header');

        headers.forEach(header => {
            header.addEventListener('click', function() {
                const content = this.nextElementSibling;

                // Alternar el contenido
                content.style.display = content.style.display === "block" ? "none" : "block";
            });
        });

        