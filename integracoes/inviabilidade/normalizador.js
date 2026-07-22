function normalizarTexto(valor) {
  return String(valor || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .trim()
    .toLowerCase();
}

function normalizarCategoriaInviabilidade(motivo) {
  const texto = normalizarTexto(motivo);

  if (!texto) {
    return "OUTRA";
  }

  if (texto.includes("cto lotada")) {
    return "CTO_LOTADA";
  }

  if (texto.includes("sem cto")) {
    return "SEM_CTO";
  }

  if (texto.includes("metragem")) {
    return "METRAGEM";
  }

  if (texto.includes("estrutura")) {
    return "ESTRUTURA";
  }

  if (texto.includes("fibrasil")) {
    return "FIBRASIL";
  }

  return "OUTRA";
}

function ehMotivoDeInviabilidade(motivo) {
  const categoria =
    normalizarCategoriaInviabilidade(motivo);

  return categoria !== "OUTRA";
}

function gerarCodigoMotivo(motivo) {
  const texto = normalizarTexto(motivo);

  if (!texto) {
    return null;
  }

  return texto
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 80)
    .toUpperCase();
}

module.exports = {
  normalizarCategoriaInviabilidade,
  ehMotivoDeInviabilidade,
  gerarCodigoMotivo
};