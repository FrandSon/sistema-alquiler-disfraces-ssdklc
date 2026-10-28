/**
 * Controlador Frontend UI/UX y Seguridad (S-SDLC)
 * Compatible con Content-Security-Policy: script-src 'self' (Sin unsafe-inline)
 */
document.addEventListener("DOMContentLoaded", () => {
    "use strict";

    // =========================================================================
    // 1. GESTIÓN NATIVA DE MODALES (<dialog>) Y ACCESIBILIDAD DE TECLADO
    // =========================================================================
    const openModalButtons = document.querySelectorAll("[data-dialog-open]");
    const closeModalButtons = document.querySelectorAll("[data-dialog-close]");

    openModalButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-dialog-open");
            const dialog = document.getElementById(targetId);
            if (!dialog || typeof dialog.showModal !== "function") return;

            // Poblar datos contextuales de forma segura (usando textContent / value)
            populateDialogContext(btn, dialog);

            dialog.showModal();

            // Enfocar el primer control interactivo dentro del modal (WCAG 2.4.3)
            const firstInput = dialog.querySelector("input:not([type='hidden']), select, textarea, button");
            if (firstInput) {
                firstInput.focus();
            }
        });
    });

    closeModalButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            const dialog = btn.closest("dialog");
            if (dialog && dialog.open) {
                dialog.close();
            }
        });
    });

    // Cerrar <dialog> al hacer clic fuera del contenedor (sobre el ::backdrop)
    document.querySelectorAll("dialog.native-modal").forEach((dialog) => {
        dialog.addEventListener("click", (event) => {
            const rect = dialog.getBoundingClientRect();
            const clickedInDialog =
                rect.top <= event.clientY &&
                event.clientY <= rect.top + rect.height &&
                rect.left <= event.clientX &&
                event.clientX <= rect.left + rect.width;

            if (!clickedInDialog) {
                dialog.close();
            }
        });
    });

    // =========================================================================
    // 2. INYECCIÓN SEGURA DE DATOS EN MODALES (Prevención DOM XSS - RS-09)
    // =========================================================================
    function populateDialogContext(triggerButton, dialogElement) {
        // Caso A: Modal de Liquidación de Devolución e Incidencias (RF-06)
        if (dialogElement.id === "dialog-devolucion") {
            const actionUrl = triggerButton.getAttribute("data-action-url") || "";
            const sku = triggerButton.getAttribute("data-sku") || "";
            const cliente = triggerButton.getAttribute("data-cliente") || "";
            const garantia = parseFloat(triggerButton.getAttribute("data-garantia") || "0");
            const fechaLimite = triggerButton.getAttribute("data-fecha-limite") || "";

            const form = dialogElement.querySelector("#form-devolucion");
            const labelResumen = dialogElement.querySelector("#devolucion-resumen-texto");
            const inputGarantiaBase = dialogElement.querySelector("#devolucion-garantia-base");
            const inputFechaLimite = dialogElement.querySelector("#devolucion-fecha-limite");

            if (form && actionUrl) form.setAttribute("action", actionUrl);
            if (labelResumen) {
                // Uso estricto de textContent para neutralizar cualquier vector XSS
                labelResumen.textContent = `${sku} — Cliente: ${cliente} (Garantía depositada: $${garantia.toFixed(2)})`;
            }
            if (inputGarantiaBase) inputGarantiaBase.value = garantia.toFixed(2);
            if (inputFechaLimite) inputFechaLimite.value = fechaLimite;

            calcularSimulacionRetencion();
        }

        // Caso B: Modal de Confirmación de Baja de Inventario (RF-03 / RS-05)
        if (dialogElement.id === "dialog-confirmar-baja") {
            const actionUrl = triggerButton.getAttribute("data-action-url") || "";
            const sku = triggerButton.getAttribute("data-sku") || "";
            const nombre = triggerButton.getAttribute("data-nombre") || "";

            const form = dialogElement.querySelector("#form-baja-disfraz");
            const skuTarget = dialogElement.querySelector("#baja-disfraz-detalle");

            if (form && actionUrl) form.setAttribute("action", actionUrl);
            if (skuTarget) {
                skuTarget.textContent = `${sku} (${nombre})`;
            }
        }
    }

    // =========================================================================
    // 3. SIMULADOR EN TIEMPO REAL DE RETENCIÓN DE GARANTÍA (RF-06)
    // =========================================================================
    const selectIncidencia = document.getElementById("select-tipo-incidencia");
    if (selectIncidencia) {
        selectIncidencia.addEventListener("change", calcularSimulacionRetencion);
    }

    function calcularSimulacionRetencion() {
        const inputGarantiaBase = document.getElementById("devolucion-garantia-base");
        const inputFechaLimite = document.getElementById("devolucion-fecha-limite");
        const outputEstimado = document.getElementById("retencion-estimada-monto");

        if (!inputGarantiaBase || !selectIncidencia || !outputEstimado) return;

        const deposito = parseFloat(inputGarantiaBase.value || "0");
        const tipoIncidencia = selectIncidencia.value;
        const fechaLimiteStr = inputFechaLimite ? inputFechaLimite.value : "";

        let porcentaje = 0.0;

        // Verificar si existe retraso respecto a la fecha actual
        if (fechaLimiteStr) {
            const hoy = new Date();
            hoy.setHours(0, 0, 0, 0);
            const partes = fechaLimiteStr.split("-");
            if (partes.length === 3) {
                const fechaLim = new Date(
                    parseInt(partes[0], 10),
                    parseInt(partes[1], 10) - 1,
                    parseInt(partes[2], 10)
                );
                if (hoy > fechaLim) {
                    porcentaje += 0.25; // +25% por mora en devolución
                }
            }
        }

        if (tipoIncidencia === "Mancha Grave") {
            porcentaje += 0.30;
        } else if (tipoIncidencia === "Dano Parcial") {
            porcentaje += 0.50;
        } else if (tipoIncidencia === "Perdida o Dano Total") {
            porcentaje = 1.00;
        }

        porcentaje = Math.min(1.0, porcentaje);
        const montoRetenido = (deposito * porcentaje).toFixed(2);
        outputEstimado.textContent = `$${montoRetenido} (${Math.round(porcentaje * 100)}%)`;
    }

    // =========================================================================
    // 4. VALIDACIÓN SEMÁNTICA DE FECHAS Y SUGERENCIA DE GARANTÍA (RS-07)
    // =========================================================================
    const inputFechaSalida = document.getElementById("ticket-fecha-salida");
    const inputFechaRetorno = document.getElementById("ticket-fecha-retorno");
    const selectDisfrazTicket = document.getElementById("ticket-disfraz-id");
    const inputDepositoTicket = document.getElementById("ticket-deposito-garantia");
    const alertaFechas = document.getElementById("ticket-alerta-fechas");

    // Pre-cargar fecha actual por defecto en emisión de tickets
    if (inputFechaSalida && !inputFechaSalida.value) {
        const hoyIso = new Date().toISOString().split("T")[0];
        inputFechaSalida.value = hoyIso;
        if (inputFechaRetorno) {
            inputFechaRetorno.min = hoyIso;
        }
    }

    function validarCoherenciaFechas() {
        if (!inputFechaSalida || !inputFechaRetorno) return true;
        if (inputFechaSalida.value) {
            inputFechaRetorno.min = inputFechaSalida.value;
        }
        if (inputFechaSalida.value && inputFechaRetorno.value) {
            if (inputFechaRetorno.value < inputFechaSalida.value) {
                inputFechaRetorno.setCustomValidity(
                    "La fecha límite de retorno debe ser igual o posterior a la fecha de salida (RS-07)."
                );
                if (alertaFechas) {
                    alertaFechas.hidden = false;
                }
                return false;
            }
        }
        inputFechaRetorno.setCustomValidity("");
        if (alertaFechas) {
            alertaFechas.hidden = true;
        }
        return true;
    }

    if (inputFechaSalida && inputFechaRetorno) {
        inputFechaSalida.addEventListener("change", validarCoherenciaFechas);
        inputFechaRetorno.addEventListener("change", validarCoherenciaFechas);
    }

    // Autocompletar depósito de garantía sugerido al elegir un disfraz disponible
    if (selectDisfrazTicket && inputDepositoTicket) {
        selectDisfrazTicket.addEventListener("change", () => {
            const selectedOption = selectDisfrazTicket.options[selectDisfrazTicket.selectedIndex];
            if (selectedOption) {
                const garantiaSugerida = selectedOption.getAttribute("data-garantia");
                if (garantiaSugerida) {
                    inputDepositoTicket.value = parseFloat(garantiaSugerida).toFixed(2);
                }
            }
        });
    }
});
