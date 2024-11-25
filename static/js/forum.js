let x = document.getElementsByClassName("fa-xmark");
for (let i = 0; i < x.length; i++) {
    x[i].addEventListener("click", function() {
        this.parentElement.parentElement.remove();
    })
}
const usernameElement = document.getElementById("Username");
const pf_btn = document.getElementById("pf_btn");
usernameElement.style.cursor = "pointer";
const loginBtn = document.getElementById("login_btn");
const logoutBtn = document.getElementById("btn-logout");
const registerBtn = document.getElementById("register_btn");
const bug_tbn = document.querySelector(".bug-tbn")

if (usernameElement && usernameElement.textContent.trim() !== "") {
    loginBtn.style.display = "none";
    registerBtn.style.display = "none";
    usernameElement.style.display = "block";
    pf_btn.style.display = "block";
    logoutBtn.style.display = "block";
    bug_tbn.style.display = "block"
} else {
    loginBtn.style.display = "block";    
    registerBtn.style.display = "block";
    if (usernameElement) {
        pf_btn.style.display = "none";
        usernameElement.style.display = "none";
        logoutBtn.style.display = "none";
        bug_tbn.style.display = "none";
    }
}
document.addEventListener("DOMContentLoaded", function() {

function cookieExists(name) {
    const cookies = document.cookie.split('; ');
    return cookies.some(cookie => cookie.startsWith(name + '='));
}

if (cookieExists('Guest_token')) {
    const form = document.querySelector('.post-form');
    if (form) {
        form.querySelectorAll('input, textarea, button').forEach(element => {
            element.disabled = true;
            form.style.opacity = "40%"
        })
    }
}
})
const commentBtns = document.querySelectorAll("#comment-btn");
const commentForms = document.querySelectorAll("#comment-form");

commentForms.forEach(form => {
    form.style.display = "none";
});

commentBtns.forEach((btn, index) => {
    btn.addEventListener("click", function() {
        if (commentForms[index].style.display === "none") {
            commentForms[index].style.display = "block";
        } else {
            commentForms[index].style.display = "none";
        }
    });
});

const dropdown = document.querySelector(".dropdown");
const dropdownContent = document.querySelector(".dropdown-content");
const btnLogout = document.getElementById("btn-logout-dropdown");

dropdown.addEventListener("click", () => {
dropdownContent.style.display = dropdownContent.style.display === "block" ? "none" : "block";
});

btnLogout.addEventListener("click", () => {
window.location.href = "/logout";
});

//! checking the input are they filled
document.querySelector(".post-form").addEventListener("submit", function (event) {
const checkboxes = [...document.getElementsByName("type")]
const checksContainer = document.querySelector(".checks-container")
const isChecked = checkboxes.some(checkbox => checkbox.checked)

if (!isChecked) {
const validationError = document.createElement("p")
validationError.textContent = "Please select at least one type"
validationError.style.color = "#ff4b4b"
validationError.style.marginTop = "20px"
validationError.classList.add("validation-error")
event.preventDefault();

if (!document.querySelector(".validation-error")) {
    checksContainer.appendChild(validationError)
}
}
});


// Function to send AJAX request
function sendReaction(postId, reactionType, callback) {
fetch("/api/postreact", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({
        post_id: postId,
        reaction_type: reactionType
    })
})
.then(response => {
    if (!response.ok) {
        throw new Error("Failed to react.");
    }
    return response.json();
})
.then(data => {
    callback(data);
})
.catch(error => {
    console.error("Error:", error);
});
}

// Add event listeners for like buttons
document.querySelectorAll(".like-btn").forEach(button => {
button.addEventListener("click", function(event) {
    event.preventDefault();
    const postId = this.getAttribute("data-post-id");
    sendReaction(postId, "LIKE", function(data) {
        if (data.success) {
        // Update the like count
        const likeCount = button.nextElementSibling;
        likeCount.textContent = data.likes;

        // Update the dislike count
        const dislikeButton = button.parentElement.querySelector(".dislike-btn");
        const dislikeCount = dislikeButton.nextElementSibling;
        dislikeCount.textContent = data.dislikes;
        }
    });
});
});



// Add event listeners for dislike buttons
document.querySelectorAll(".dislike-btn").forEach(button => {
button.addEventListener("click", function(event) {
    event.preventDefault();
    const postId = this.getAttribute("data-post-id");
    sendReaction(postId, "DISLIKE", function(data) {
        if (data.success) {
        // Update the like count
        const DislikeCount = button.nextElementSibling;
        DislikeCount.textContent = data.dislikes;

        // Update the dislike count
        const likeButton = button.parentElement.querySelector(".like-btn");
        const likeCount = likeButton.nextElementSibling;
        likeCount.textContent = data.likes;
        }
    });
});
});
function sendComment(postId, commentContent, callback) {
    fetch("/api/postComment", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            post_id: postId,
            comment_content: commentContent
        })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error("Failed to post comment.");
        }
        return response.json();
    })
    .then(data => {
        callback(data);
    })
    .catch(error => {
        console.error("Error:", error);
    });
}

document.querySelectorAll(".comment-btn").forEach(button => {
    button.addEventListener("click", function(event) {
        event.preventDefault();

        const postId = this.previousElementSibling.getAttribute("post-id");
        const commentContent = this.previousElementSibling.value;

        sendComment(postId, commentContent, function(data) {
            console.log(data)
            if (data.success) {

                button.previousElementSibling.value = ''; // Clear the input field

                // Dynamically create and display the new comment
                const newCommentDiv = document.createElement("div");
                newCommentDiv.className = "comment-content";

                // Assuming `data.comment` contains the new comment details
                newCommentDiv.innerHTML = `
                        <div class="comment-header">
                            <div class="flex">
                                <i id="user_icon" class="fa-solid fa-user"></i>
                                <strong style="font-size: 14px;">${data.comment.username}</strong>
                            </div>
                            <p style="font-size: 12px;">${data.comment.date}</p>
                        </div>   
                        <p id="thecomment">${data.comment.content}</p>
                        <form action="/" method="POST">
                            <input type="hidden" name="query" value="comment_react">
                            <input type="hidden" name="comment_id" value="${data.comment.id}">
                            <div class="like_dislike-comments">
                                <button name="like-btn" value="LIKE" class="reactions">
                                    <svg width="22" height="22" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                        <path d="M12 4 3 15h6v5h6v-5h6z" class="icon_svg-stroke icon_svg-fill" 
                                              stroke-width="1.5" stroke="#e0e0e0" fill="none" stroke-linejoin="round"></path>
                                    </svg>
                                </button>
                                <span class="counter-holder">0</span>
                            
                                <button name="dislike-btn" value="DISLIKE" class="reactions">
                                    <svg width="22" height="22" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                        <path d="m12 20 9-11h-6V4H9v5H3z" class="icon_svg-stroke icon_svg-fill" 
                                              stroke="#e0e0e0" fill="none" stroke-width="1.5" stroke-linejoin="round"></path>
                                    </svg>
                                </button>
                                <span class="counter-holder">0</span> 
                            </div>
                        </form>
                `;

                // Append the new comment to the comments container
                const commentsContainer = document.getElementById("comments-container");
                commentsContainer.insertBefore(newCommentDiv, commentsContainer.firstChild);

                console.log("Comment posted successfully");
            }
        });
    });
});
