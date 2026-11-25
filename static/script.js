"use strict";

const $ = (id) => document.getElementById(id);

const form = $("sign-form");
const errorMsg = $("error-msg");
const submitBtn = $("submit-btn");
const formPanel = $("form-panel");
const receiptSection = $("receipt-section");

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const DRAFT_KEY = "docbirthriot:draft";

/* ---------------------------- utilidades ---------------------------- */

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
	// agrupa de 4 em 4 caracteres, como o gpg exibe
	return fp.replace(/(.{4})/g, "$1 ").trim();
}

let toastTimer;
function toast(text) {
	const el = $("toast");
	el.textContent = text;
	el.classList.add("show");
	clearTimeout(toastTimer);
	toastTimer = setTimeout(() => el.classList.remove("show"), 2200);
}

async function copy(text, okMsg) {
	try {
		await navigator.clipboard.writeText(text);
		toast(okMsg);
	} catch {
		toast("Não deu para copiar. Selecione e copie manualmente.");
	}
}

/* ---------------------------- rascunho ---------------------------- */
// Guarda nome/email digitados para não perder ao recarregar (só neste navegador).

function loadDraft() {
	try {
		const d = JSON.parse(localStorage.getItem(DRAFT_KEY) || "{}");
		if (d.name) $("name").value = d.name;
		if (d.email) $("email").value = d.email;
	} catch {
		/* storage indisponível: ignora */
	}
}

function saveDraft() {
	try {
		localStorage.setItem(
			DRAFT_KEY,
			JSON.stringify({ name: $("name").value, email: $("email").value })
		);
	} catch {
		/* ignora */
	}
}

function clearDraft() {
	try {
		localStorage.removeItem(DRAFT_KEY);
	} catch {
		/* ignora */
	}
}

/* ---------------------------- confete ---------------------------- */

function confetti() {
	if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
	const canvas = $("confetti");
	const ctx = canvas.getContext("2d");
	const dpr = window.devicePixelRatio || 1;
	canvas.width = innerWidth * dpr;
	canvas.height = innerHeight * dpr;
	ctx.scale(dpr, dpr);

	const colors = ["#b98f2b", "#8a2b32", "#b5454c", "#f4eedd", "#6fae7c", "#3c8dbc"];
	const pieces = Array.from({ length: 160 }, () => ({
		x: innerWidth / 2 + (Math.random() - 0.5) * 120,
		y: innerHeight * 0.35,
		vx: (Math.random() - 0.5) * 12,
		vy: -Math.random() * 12 - 4,
		size: Math.random() * 6 + 4,
		rot: Math.random() * Math.PI,
		vr: (Math.random() - 0.5) * 0.3,
		color: colors[(Math.random() * colors.length) | 0],
	}));

	const start = performance.now();
	(function frame(now) {
		ctx.clearRect(0, 0, innerWidth, innerHeight);
		for (const p of pieces) {
			p.vy += 0.32;
			p.vx *= 0.99;
			p.x += p.vx;
			p.y += p.vy;
			p.rot += p.vr;
			ctx.save();
			ctx.translate(p.x, p.y);
			ctx.rotate(p.rot);
			ctx.fillStyle = p.color;
			ctx.fillRect(-p.size / 2, -p.size / 4, p.size, p.size / 2);
			ctx.restore();
		}
		if (now - start < 3500) requestAnimationFrame(frame);
		else ctx.clearRect(0, 0, innerWidth, innerHeight);
	})(start);
}

/* ---------------------------- contador ---------------------------- */

function updateCounter(total) {
	const el = $("counter");
	if (!el) return;
	el.textContent =
		total === 0 ? "ninguém assinou ainda" : total === 1 ? "1 assinatura" : `${total} assinaturas`;
}

/* ---------------------------- envio ---------------------------- */

form.addEventListener("input", saveDraft);

form.addEventListener("submit", async (e) => {
	e.preventDefault();
	errorMsg.textContent = "";

	const name = $("name").value.trim();
	const email = $("email").value.trim();
	const agree = $("agree").checked;

	if (name.length < 2) {
		errorMsg.textContent = "Informe seu nome.";
		$("name").focus();
		return;
	}
	if (!EMAIL_RE.test(email)) {
		errorMsg.textContent = "Informe um email válido.";
		$("email").focus();
		return;
	}
	if (!agree) {
		errorMsg.textContent = "É preciso marcar que você leu e concorda com o documento.";
		$("agree").focus();
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
		let data = {};
		try {
			data = await res.json();
		} catch {
			/* resposta sem JSON */
		}
		if (!res.ok) throw new Error(data.error || "Erro ao assinar o documento.");

		const verifyUrl = new URL(data.verify_url, location.origin).href;

		$("seal-code").textContent = "№ " + data.fingerprint.slice(-6);
		$("r-id").textContent = "#" + String(data.number).padStart(6, "0") + " · " + data.id;
		$("r-name").textContent = name;
		$("r-date").textContent = formatDateUTC(data.signed_at);
		$("r-fingerprint").textContent = formatFingerprint(data.fingerprint);
		$("receipt-block").textContent = data.signed_block;
		$("r-verify").href = data.verify_url;
		$("r-download").href = `/api/signatures/${encodeURIComponent(data.id)}/download`;
		$("copy-link").onclick = () => copy(verifyUrl, "Link copiado!");
		$("copy-block").onclick = () => copy(data.signed_block, "Bloco PGP copiado!");

		updateCounter(data.number);
		clearDraft();

		formPanel.classList.add("hidden");
		receiptSection.classList.remove("hidden");
		receiptSection.focus({ preventScroll: true });
		receiptSection.scrollIntoView({ behavior: "smooth", block: "start" });
		confetti();
	} catch (err) {
		errorMsg.textContent = err.message;
		submitBtn.disabled = false;
		submitBtn.querySelector(".btn-label").textContent = "Assinar documento";
	}
});

loadDraft();
