"use strict";

// Datas e fingerprint legíveis na página de um recibo
document.querySelectorAll(".js-date").forEach((el) => {
	const d = new Date(el.dataset.iso);
	if (!isNaN(d)) {
		el.textContent =
			d.toLocaleString("pt-BR", {
				day: "2-digit",
				month: "2-digit",
				year: "numeric",
				hour: "2-digit",
				minute: "2-digit",
				timeZone: "UTC",
			}) + " UTC";
	}
});
document.querySelectorAll(".js-fp").forEach((el) => {
	el.textContent = el.textContent.trim().replace(/(.{4})/g, "$1 ").trim();
});

// Verificação de um bloco PGP colado
const blockForm = document.getElementById("block-form");
if (blockForm) {
	const result = document.getElementById("block-result");
	blockForm.addEventListener("submit", async (e) => {
		e.preventDefault();
		result.className = "result mono";
		result.textContent = "Verificando…";
		try {
			const res = await fetch("/api/verify", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ signed_block: document.getElementById("block").value }),
			});
			const data = await res.json();
			if (data.verified) {
				result.classList.add("ok");
				result.textContent = "✅ Assinatura válida, emitida por este servidor.";
			} else {
				result.classList.add("bad");
				result.textContent = "❌ " + (data.error || "Assinatura inválida ou de outro servidor.");
			}
		} catch {
			result.classList.add("bad");
			result.textContent = "Erro ao verificar. Tente novamente.";
		}
	});
}
