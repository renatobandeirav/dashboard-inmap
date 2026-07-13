const PIPERUN_BASE_URL =
  process.env.PIPERUN_BASE_URL || "https://api.pipe.run/v1";

const TEMPO_LIMITE_REQUISICAO_MS = 20000;

function obterTokenPiperun() {
  const token = String(process.env.PIPERUN_TOKEN || "").trim();

  if (!token) {
    throw new Error("PIPERUN_TOKEN não configurado no arquivo .env.");
  }

  return token;
}

function montarUrl(endpoint, parametros = {}) {
  const caminho = String(endpoint || "").replace(/^\/+/, "");
  const url = new URL(`${PIPERUN_BASE_URL}/${caminho}`);

  Object.entries(parametros).forEach(([chave, valor]) => {
    if (
      valor === undefined ||
      valor === null ||
      valor === ""
    ) {
      return;
    }

    if (Array.isArray(valor)) {
      valor.forEach(item => {
        url.searchParams.append(chave, String(item));
      });

      return;
    }

    url.searchParams.set(chave, String(valor));
  });

  return url;
}

async function lerRespostaJson(response) {
  const texto = await response.text();

  if (!texto) {
    return {};
  }

  try {
    return JSON.parse(texto);
  } catch {
    throw new Error(
      `A Piperun retornou uma resposta inválida. HTTP ${response.status}.`
    );
  }
}

async function requisitarPiperun(
  endpoint,
  {
    metodo = "GET",
    parametros = {},
    corpo = null,
    timeoutMs = TEMPO_LIMITE_REQUISICAO_MS
  } = {}
) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const url = montarUrl(endpoint, parametros);

    const headers = {
      token: obterTokenPiperun(),
      Accept: "application/json"
    };

    const opcoes = {
      method: metodo,
      headers,
      signal: controller.signal
    };

    if (corpo !== null && corpo !== undefined) {
      headers["Content-Type"] = "application/json";
      opcoes.body = JSON.stringify(corpo);
    }

    const response = await fetch(url, opcoes);
    const resultado = await lerRespostaJson(response);

    if (!response.ok || resultado?.success === false) {
      const erro = new Error(
        resultado?.message ||
        `Erro na API da Piperun. HTTP ${response.status}.`
      );

      erro.status = response.status;
      erro.retornoPiperun = resultado;

      throw erro;
    }

    return resultado;
  } catch (erro) {
    if (erro?.name === "AbortError") {
      throw new Error(
        `A API da Piperun excedeu o limite de ${timeoutMs / 1000} segundos.`
      );
    }

    throw erro;
  } finally {
    clearTimeout(timer);
  }
}

async function buscarDeals({
  pipelineId,
  personId,
  stageId,
  show = 150,
  page
} = {}) {
  const resultado = await requisitarPiperun("deals", {
    parametros: {
      pipeline_id: pipelineId,
      person_id: personId,
      stage_id: stageId,
      show,
      page
    }
  });

  return {
    dados: Array.isArray(resultado?.data)
      ? resultado.data
      : [],
    meta: resultado?.meta || null,
    links: resultado?.links || null,
    retornoCompleto: resultado
  };
}

async function buscarPessoaPorId(personId) {
  if (!personId) {
    return null;
  }

  const resultado = await requisitarPiperun(
    `persons/${encodeURIComponent(personId)}`
  );

  return resultado?.data || null;
}

async function buscarUsuariosDoDeal(dealId) {
  if (!dealId) {
    return [];
  }

  const resultado = await requisitarPiperun(
    `deals/${encodeURIComponent(dealId)}/users`
  );

  return Array.isArray(resultado?.data)
    ? resultado.data
    : [];
}


async function buscarTodosDeals({
  pipelineId,
  personId,
  stageId,
  show = 100,
  limitePaginas = 100
} = {}) {
  const todosOsDeals = [];
  let paginaAtual = 1;
  let totalPaginas = 1;

  do {
    const resultado = await buscarDeals({
      pipelineId,
      personId,
      stageId,
      show,
      page: paginaAtual
    });

    todosOsDeals.push(...resultado.dados);

    totalPaginas = Number(
      resultado.meta?.total_pages || 1
    );

    paginaAtual += 1;

  } while (
    paginaAtual <= totalPaginas &&
    paginaAtual <= limitePaginas
  );

  return {
    dados: todosOsDeals,
    total: todosOsDeals.length,
    totalPaginas
  };
}

module.exports = {
  requisitarPiperun,
  buscarDeals,
  buscarPessoaPorId,
  buscarUsuariosDoDeal,
  buscarTodosDeals
};