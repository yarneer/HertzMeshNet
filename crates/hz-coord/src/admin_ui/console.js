(function () {
  var links = document.querySelectorAll("nav a");
  var who = document.getElementById("who");

  function mark() {
    var hash = location.hash;
    for (var i = 0; i < links.length; i++) {
      if (hash && links[i].getAttribute("href") === hash) {
        links[i].setAttribute("aria-current", "page");
      } else {
        links[i].removeAttribute("aria-current");
      }
    }
  }

  window.addEventListener("hashchange", mark);
  mark();

  fetch("/admin/api/me")
    .then(function (response) {
      if (!response.ok) {
        throw new Error(String(response.status));
      }
      return response.json();
    })
    .then(function (body) {
      who.textContent = body.username || body.subject || "";
    })
    .catch(function () {
      who.textContent = "未能读取身份";
    });
})();
