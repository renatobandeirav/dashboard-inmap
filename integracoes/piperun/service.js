const {
  STAGES
} = require("./constants");

function normalizarTexto(valor) {
  if (valor === undefined || valor === null) {
    return null;
  }

  const texto = String(valor).trim();

  return texto || null;
}

function normalizarNome(nome) {
  const texto = normalizarTexto(nome);

  if (!texto) {
    return null;
  }

  return texto
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .map(palavra => {
      return palavra.charAt(0).toUpperCase() + palavra.slice(1);
    })
    .join(" ");
}

function converterNumero(valor, padrao = 0) {
  if (valor === undefined || valor === null || valor === "") {
    return padrao;
  }

  if (typeof valor === "number") {
    return Number.isFinite(valor) ? valor : padrao;
  }

  const texto = String(valor).trim();

  if (!texto) {
    return padrao;
  }

  let textoNormalizado = texto;

  if (texto.includes(",")) {
    textoNormalizado = texto
      .replace(/\./g, "")
      .replace(",", ".");
  }

  const numero = Number(textoNormalizado);

  return Number.isFinite(numero) ? numero : padrao;
}

function converterInteiro(valor) {
  if (valor === undefined || valor === null || valor === "") {
    return null;
  }

  const numero = Number.parseInt(String(valor).trim(), 10);

  return Number.isFinite(numero) ? numero : null;
}

function converterBooleano(valor) {
  if (typeof valor === "boolean") {
    return valor;
  }

  const texto = String(valor || "")
    .trim()
    .toLowerCase();

  return [
    "true",
    "1",
    "sim",
    "s",
    "yes"
  ].includes(texto);
}

function converterDataMariaDB(valor) {
  const texto = normalizarTexto(valor);

  if (!texto) {
    return null;
  }

  const dataNormalizada = texto
    .replace("T", " ")
    .replace(/\.\d+Z?$/, "")
    .replace(/Z$/, "");

  const correspondencia = dataNormalizada.match(
    /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/
  );

  if (!correspondencia) {
    return null;
  }

  return `${correspondencia[1]} ${correspondencia[2]}`;
}

function extrairCamposDescricao(descricao) {
  const campos = {};

  if (!descricao) {
    return campos;
  }

  String(descricao)
    .split(/\r?\n/)
    .forEach(linha => {
      const indiceSeparador = linha.indexOf(":");

      if (indiceSeparador <= 0) {
        return;
      }

      const chave = linha
        .slice(0, indiceSeparador)
        .trim();

      const valor = linha
        .slice(indiceSeparador + 1)
        .trim();

      if (!chave) {
        return;
      }

      campos[chave] = valor || null;
    });

  return campos;
}

function extrairCoordenadas(valor) {
  const texto = normalizarTexto(valor);

  if (!texto) {
    return {
      latitude: null,
      longitude: null
    };
  }

  const partes = texto
    .split(",")
    .map(item => item.trim());

  if (partes.length !== 2) {
    return {
      latitude: null,
      longitude: null
    };
  }

  const latitude = Number(partes[0]);
  const longitude = Number(partes[1]);

  return {
    latitude: Number.isFinite(latitude)
      ? latitude
      : null,

    longitude: Number.isFinite(longitude)
      ? longitude
      : null
  };
}

function obterNomeCliente(deal, campos) {
  return normalizarTexto(
    campos["Nome Completo"] ||
    deal?.title ||
    `Oportunidade ${deal?.id || ""}`
  );
}

function transformarDealPiperun(deal) {
  if (!deal?.id) {
    throw new Error(
      "Oportunidade Piperun sem identificador."
    );
  }

  const etapa = STAGES[deal.stage_id];

  if (!etapa) {
    return null;
  }

  const campos = extrairCamposDescricao(
    deal.description
  );

  const coordenadas = extrairCoordenadas(
    campos["Latitude/Longitude"]
  );

  const vendedorNome = normalizarNome(
    campos["User Nome"]
  );

  const responsavelNome = normalizarNome(
    deal?.owner?.name
  );

  const planoNome =
    normalizarTexto(
      campos["Plano Nome Pipe Run"]
    );

  const dataCadastroPedido =
    converterDataMariaDB(
      campos["Cadastro Em"]
    );

  const dataEntradaFunil =
    converterDataMariaDB(
      deal.created_at
    );

  const dataEntradaEtapa =
    converterDataMariaDB(
      deal.stage_changed_at ||
      deal.last_stage_updated_at
    );

  return {
    deal_id: converterInteiro(deal.id),
    person_id: converterInteiro(deal.person_id),
    pipeline_id: converterInteiro(deal.pipeline_id),
    stage_id: converterInteiro(deal.stage_id),

    etapa,
    status_piperun: converterInteiro(deal.status),

    cliente: obterNomeCliente(deal, campos),

    vendedor_nome: vendedorNome,
    vendedor_ixc_id: converterInteiro(
      campos["ID Vendedor IXC"]
    ),

    responsavel_piperun_id: converterInteiro(
      deal.owner_id ||
      deal?.owner?.id
    ),

    responsavel_piperun_nome: responsavelNome,

    cidade: normalizarTexto(
      campos["Cidade"]
    ),

    bairro: normalizarTexto(
      campos["Bairro"]
    ),

    latitude: coordenadas.latitude,
    longitude: coordenadas.longitude,

    campanha_ixc_id: converterInteiro(
      campos["ID Campanha IXC"]
    ),

    campanha_nome: normalizarTexto(
      campos["Nome Campanha"]
    ),

    canal_venda_ixc_id: converterInteiro(
      campos["ID Canal Venda IXC"]
    ),

    canal_venda_nome: normalizarTexto(
      campos["Nome Canal Venda"]
    ),

    plano_ixc_id: converterInteiro(
      campos["Plano ID Negociacao IXC"]
    ),

    plano_nome: planoNome,

    valor: converterNumero(
      deal.value,
      0
    ),

    mrr: converterNumero(
      deal.value_mrr,
      0
    ),

    instalacao_valor: converterNumero(
      campos["Instalacao Valor"],
      0
    ),

    instalacao_gratis: converterBooleano(
      campos["Instalacao Gratis"]
    )
      ? 1
      : 0,

    data_origem:
      dataCadastroPedido ||
      dataEntradaFunil,

    data_entrada_funil: dataEntradaFunil,
    data_entrada_etapa: dataEntradaEtapa,

    lead_time: converterInteiro(
      deal.lead_time
    ),

    oportunidade_origem_id: null,

    origin_id: converterInteiro(
      deal.origin_id
    ),

    criado_piperun_em:
      converterDataMariaDB(
        deal.created_at
      ),

    atualizado_piperun_em:
      converterDataMariaDB(
        deal.updated_at
      )
  };
}

function transformarListaDeals(deals = []) {
  if (!Array.isArray(deals)) {
    return [];
  }

  return deals
    .map(transformarDealPiperun)
    .filter(Boolean);
}

module.exports = {
  extrairCamposDescricao,
  extrairCoordenadas,
  transformarDealPiperun,
  transformarListaDeals,
  converterDataMariaDB,
  normalizarNome
};