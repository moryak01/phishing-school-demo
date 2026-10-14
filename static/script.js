const form = document.getElementById("check-form");
const urlInput = document.getElementById("url-input");
const checkButton = document.getElementById("check-button");
const loading = document.getElementById("loading");
const resultBlock = document.getElementById("result");
const verdictBox = document.getElementById("verdict-box");
const verdictTitle = document.getElementById("verdict-title");
const riskScore = document.getElementById("risk-score");
const reasonsList = document.getElementById("reasons-list");

function clearResult() {
    resultBlock.classList.add("hidden");
    verdictBox.className = "";
    reasonsList.innerHTML = "";
}

function showError(message) {
    clearResult();
    verdictBox.classList.add("high-risk");
    verdictTitle.textContent = "Ошибка";
    riskScore.textContent = "—";

    reasonsList.innerHTML = "";
    const li = document.createElement("li");
    li.textContent = message;
    reasonsList.appendChild(li);

    resultBlock.classList.remove("hidden");
}

function getVerdictText(verdict) {
    if (verdict === "safe") {
        return "Вероятно, безопасно";
    }
    if (verdict === "suspicious") {
        return "Подозрительно";
    }
    if (verdict === "high_risk") {
        return "Высокий риск фишинга";
    }
    return "Неизвестно";
}

function renderResult(data) {
    clearResult();

    verdictTitle.textContent = getVerdictText(data.verdict);
    riskScore.textContent = `${data.risk_score} / 100`;

    if (data.verdict === "safe") {
        verdictBox.classList.add("safe");
    } else if (data.verdict === "suspicious") {
        verdictBox.classList.add("suspicious");
    } else {
        verdictBox.classList.add("high-risk");
    }

    reasonsList.innerHTML = "";

    if (!data.reasons || data.reasons.length === 0) {
        const li = document.createElement("li");
        li.textContent = "Явных эвристических признаков фишинга не найдено.";
        reasonsList.appendChild(li);
    } else {
        data.reasons.forEach(function (reason) {
            const li = document.createElement("li");
            li.textContent = reason;
            reasonsList.appendChild(li);
        });
    }

    resultBlock.classList.remove("hidden");
}

form.addEventListener("submit", async function (event) {
    event.preventDefault();

    const url = urlInput.value.trim();

    if (!url) {
        showError("Введите ссылку.");
        return;
    }

    clearResult();
    loading.classList.remove("hidden");
    checkButton.disabled = true;
    checkButton.textContent = "Проверка...";

    try {
        const response = await fetch("/api/check", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url: url }),
        });

        const data = await response.json();

        if (!response.ok) {
            showError(data.error || "Не удалось проверить ссылку.");
            return;
        }

        renderResult(data);
    } catch (error) {
        showError("Ошибка соединения с сервером.");
    } finally {
        loading.classList.add("hidden");
        checkButton.disabled = false;
        checkButton.textContent = "Проверить";
    }
});
