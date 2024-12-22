
// Make flashed messages disappear after 7 seconds
setTimeout(function() {
    var messages = document.getElementsByClassName('flashed-messages');
    for (var i = 0; i < messages.length; i++) {
        messages[i].style.display = 'none';
    }
}, 7000); 

// Deletes tasks
document.querySelectorAll('.delete').forEach(button => {
    button.addEventListener('click', function() {
        const taskId = this.parentElement.parentElement.getAttribute('data-task_id');
        fetch('/delete-task', {
            method: 'DELETE',
            body: JSON.stringify({ id: taskId }),
            headers: { 'Content-Type': 'application/json' }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                this.parentElement.parentElement.remove();
            }
        });
    });
});


// Marks tasks as complete
document.querySelectorAll('.complete').forEach(button => {
    button.addEventListener('click', function() {
        const taskId = this.parentElement.parentElement.getAttribute('data-task_id');
        fetch('/mark-complete', {
            method: 'PUT',
            body: JSON.stringify({ id: taskId }),
            headers: { 'Content-Type': 'application/json' }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const completedSection = document.querySelector('#completed-tasks');
                completedSection.appendChild(this.parentElement.parentElement);

                this.remove();
            }
        });
    });
});