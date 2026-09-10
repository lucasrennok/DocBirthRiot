const form = document.getElementById("sign-form");
const errorMsg = document.getElementById("error-msg");
const submitBtn = document.getElementById("submit-btn");
const formPanel = document.getElementById("form-panel");
const receiptSection = document.getElementById("receipt-section");

function formatDateUTC(isoString) {
	const d = new Date(isoString);
	return (
		d.toLocaleString("pt-BR", {
			day: "2-digit",
			month: "2-digit",
			year: "numeric",
			hour: "2-digit",
			minute: "2-digit",
			timeZone: "UTC",
		}) + " UTC"
	);
}

function formatFingerprint(fp) {
	// agrupa de 4 em 4 caracteres, como o gpg costuma exibir
	return fp.replace(/(.{4})/g, "$1 ").trim();
}

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

form.addEventListener("submit", async (e) => {
	e.preventDefault();
	errorMsg.textContent = "";

	const name = document.getElementById("name").value.trim();
	const email = document.getElementById("email").value.trim();
	const agree = document.getElementById("agree").checked;

	if (!name || name.length < 2) {
		errorMsg.textContent = "Informe seu nome.";
		document.getElementById("name").focus();
		return;
	}
	if (!EMAIL_RE.test(email)) {
		errorMsg.textContent = "Informe um email válido.";
		document.getElementById("email").focus();
		return;
	}
	if (!agree) {
		errorMsg.textContent =
			"É preciso marcar que você leu e concorda com o documento.";
		document.getElementById("agree").focus();
		return;
	}

	submitBtn.disabled = true;
	submitBtn.querySelector(".btn-label").textContent = "Assinando…";

	try {
		const res = await fetch("/api/sign", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name, email, agree }),
		});
		const data = await res.json();

		if (!res.ok) {
			throw new Error(data.error || "Erro ao assinar o documento.");
		}

		// document.getElementById("seal-code").textContent =
		// 	"№ " + data.fingerprint.slice(-6);
		document.getElementById("r-id").textContent =
			"#" + String(data.id).padStart(6, "0");
		document.getElementById("r-name").textContent = name;
		// document.getElementById("r-date").textContent = formatDateUTC(
		// 	data.signed_at
		// );
		// document.getElementById("r-fingerprint").textContent = formatFingerprint(
		// 	data.fingerprint
		// );
		document.getElementById("receipt-block").textContent = data.signed_block;

		formPanel.classList.add("hidden");
		receiptSection.classList.remove("hidden");
		receiptSection.scrollIntoView({ behavior: "smooth", block: "start" });
	} catch (err) {
		errorMsg.textContent = err.message;
		submitBtn.disabled = false;
		submitBtn.querySelector(".btn-label").textContent = "Assinar documento";
	}
});
