function deleteTask(task_id) {
    fetch("/delete-task", {
        method: "POST",
        body: JSON.stringify({ taask_id: task_id })
    }).then((_res) => {
        window.location.href = "/home";
    })
}